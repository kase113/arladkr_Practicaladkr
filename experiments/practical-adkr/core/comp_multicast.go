package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type compKeyWire struct {
	Kind           string             `json:"kind"`
	SID            string             `json:"sid"`
	Epoch          uint64             `json:"epoch"`
	Recipient      int                `json:"recipient,omitempty"`
	Sender         int                `json:"sender"`
	SelectedDigest []byte             `json:"selected_digest"`
	Share          CompPublicKeyShare `json:"share"`
}

type compCollectorOutput struct {
	recipient  int
	group      []byte
	public     map[int][]byte
	completion CompKeyCompletionCertificate
	err        error
}

type compKeyService struct {
	cfg       Config
	addresses map[int]string
	channels  map[int]chan compKeyWire
	listeners map[int]net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func practicalCompAddresses(cfg Config, committee []int) (map[int]string, error) {
	if configured := parseNodeAddrMap(cfg.CompNodeAddrs); len(configured) > 0 {
		for _, id := range committee {
			if strings.TrimSpace(configured[id]) == "" {
				return nil, fmt.Errorf("CompProve address missing for node %d", id)
			}
		}
		return configured, nil
	}
	protocol := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	derived := make(map[int]string, len(committee))
	for _, id := range committee {
		host, portText, err := net.SplitHostPort(protocol[id])
		if err != nil {
			return nil, fmt.Errorf("derive CompProve address for node %d: %w", id, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port+10000 > 65535 {
			return nil, fmt.Errorf("invalid derived CompProve port for node %d", id)
		}
		derived[id] = net.JoinHostPort(host, strconv.Itoa(port+10000))
	}
	return derived, nil
}

func startCompKeyService(ctx context.Context, cfg Config, committee []int, localPrivate map[int]*big.Int) (*compKeyService, error) {
	addresses, err := practicalCompAddresses(cfg, committee)
	if err != nil {
		return nil, err
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	service := &compKeyService{
		cfg: cfg, addresses: addresses,
		channels: make(map[int]chan compKeyWire), listeners: make(map[int]net.Listener), cancel: cancel,
	}
	for _, recipient := range committee {
		if localPrivate[recipient] == nil {
			continue
		}
		_, port, splitErr := net.SplitHostPort(addresses[recipient])
		if splitErr != nil {
			service.close()
			return nil, splitErr
		}
		listener, listenErr := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if listenErr != nil {
			service.close()
			return nil, fmt.Errorf("listen persistent CompProve node %d: %w", recipient, listenErr)
		}
		service.listeners[recipient] = listener
		service.channels[recipient] = make(chan compKeyWire, len(committee)*len(committee)*2)
		service.wg.Add(1)
		go serveCompKeyWires(serviceCtx, cfg, recipient, listener, service.channels[recipient], &service.wg)
	}
	if len(service.listeners) == 0 {
		service.close()
		return nil, errors.New("CompProve service has no local listener")
	}
	return service, nil
}

// closeCompServiceAfterGrace keeps the CompProve responders reachable for a
// bounded window after a successful epoch so slower peers can still satisfy
// their readiness barriers; failed epochs and a zero grace close immediately.
func closeCompServiceAfterGrace(service *compKeyService, ctx context.Context) {
	if service == nil {
		return
	}
	grace := durationFromEnvMsOr("PRACTICAL_RESPONDER_GRACE_MS", 0)
	if grace <= 0 || ctx == nil || ctx.Err() != nil {
		service.close()
		return
	}
	go func() {
		select {
		case <-time.After(grace):
		case <-ctx.Done():
		}
		service.close()
	}()
}
func (service *compKeyService) close() {
	if service == nil {
		return
	}
	if service.cancel != nil {
		service.cancel()
	}
	for _, listener := range service.listeners {
		_ = listener.Close()
	}
	service.wg.Wait()
}

func compKeyDerivationTimeout(cfg Config) time.Duration {
	timeout := durationFromEnvMsOr("PRACTICAL_KEY_DERIVE_TIMEOUT_MS", 45*time.Second)
	if cfg.RouteSendTimeout > 0 && 12*cfg.RouteSendTimeout > timeout {
		timeout = 12 * cfg.RouteSendTimeout
	}
	return timeout
}

func runCompKeyDerivationMulticast(
	ctx context.Context,
	cfg Config,
	newCommittee []int,
	selected []int,
	transcripts map[int]*DXTTranscript,
	localShares map[int]map[int]SharePair,
	paillierPrivate map[int]*PaillierPrivateKey,
	compKeys *practicalCompKeySet,
	service *compKeyService,
	dxt *DXTBackend,
) (map[int][]byte, []byte, map[int][]byte, map[int]CompKeyCompletionCertificate, error) {
	if compKeys == nil || len(compKeys.public) != len(newCommittee) {
		return nil, nil, nil, nil, errors.New("invalid CompProve key set")
	}
	threshold := len(newCommittee) - cfg.F
	if threshold != dxt.sharingDegree+1 || threshold <= 0 {
		return nil, nil, nil, nil, errors.New("CompProve threshold/degree mismatch")
	}
	selectedDigest, canonicalSelected, err := compSelectedDigest(selected, transcripts)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Transcript validity was established by the preceding partial-verify
	// phase (or its explicitly selected full-local variant). Re-running the
	// complete transcript verification here duplicated the O(k*n) crypto work
	// for every receiver without changing the selected set or predicate.

	localIDs := make([]int, 0, len(compKeys.private))
	for _, id := range newCommittee {
		if compKeys.private[id] != nil {
			localIDs = append(localIDs, id)
		}
	}
	sort.Ints(localIDs)
	if len(localIDs) == 0 {
		return nil, nil, nil, nil, errors.New("CompProve has no local new-committee identity")
	}
	if service == nil {
		return nil, nil, nil, nil, errors.New("CompProve persistent service is unavailable")
	}
	addrMap := service.addresses
	for _, id := range newCommittee {
		if strings.TrimSpace(addrMap[id]) == "" {
			return nil, nil, nil, nil, fmt.Errorf("CompProve missing address for new node %d", id)
		}
	}

	stageCtx, cancel := context.WithTimeout(ctx, compKeyDerivationTimeout(cfg))
	defer cancel()
	for _, recipient := range localIDs {
		if service.channels[recipient] == nil || service.listeners[recipient] == nil {
			return nil, nil, nil, nil, fmt.Errorf("CompProve persistent service missing local node %d", recipient)
		}
	}
	if err := waitCompKeyServiceReady(stageCtx, cfg, newCommittee, service); err != nil {
		return nil, nil, nil, nil, err
	}

	prepared := make(map[int]compKeyWire, len(localIDs))
	newShares := make(map[int][]byte, len(localIDs))
	for _, sender := range localIDs {
		share, secret, proveErr := compProve(
			cfg.SID, cfg.Epoch, sender, canonicalSelected, selectedDigest, transcripts,
			localShares, paillierPrivate[sender], compKeys.private[sender], compKeys.public[sender],
		)
		if proveErr != nil {
			return nil, nil, nil, nil, fmt.Errorf("CompProve node %d: %w", sender, proveErr)
		}
		prepared[sender] = compKeyWire{
			Kind: "key", SID: cfg.SID, Epoch: cfg.Epoch, Sender: sender,
			SelectedDigest: append([]byte(nil), selectedDigest...), Share: share,
		}
		newShares[sender] = secret.Bytes()
	}

	outputs := make(chan compCollectorOutput, len(localIDs))
	for _, recipient := range localIDs {
		recipient := recipient
		go collectCompKeyWires(
			stageCtx, cfg, recipient, newCommittee, canonicalSelected, selectedDigest,
			transcripts, compKeys.public, dxt.recipientSignPriv[recipient], dxt.recipientSignPub[recipient],
			addrMap, threshold, service.channels[recipient], outputs,
		)
	}

	var sendWG sync.WaitGroup
	for sender, wire := range prepared {
		for _, recipient := range newCommittee {
			if local, ok := service.channels[recipient]; ok {
				local <- wire
				continue
			}
			sendWG.Add(1)
			go func(from, to int, addr string, message compKeyWire) {
				defer sendWG.Done()
				sendCompKeyWire(stageCtx, cfg, from, to, addr, message)
			}(sender, recipient, addrMap[recipient], wire)
		}
	}

	var group []byte
	var public map[int][]byte
	completionCertificates := make(map[int]CompKeyCompletionCertificate, len(localIDs))
	for range localIDs {
		output := <-outputs
		if output.err != nil {
			cancel()
			sendWG.Wait()
			return nil, nil, nil, nil, fmt.Errorf("CompProve recipient %d: %w", output.recipient, output.err)
		}
		if group == nil {
			group = append([]byte(nil), output.group...)
			public = output.public
		} else if !bytes.Equal(group, output.group) || !samePublicShareMap(public, output.public) {
			cancel()
			sendWG.Wait()
			return nil, nil, nil, nil, errors.New("CompProve collectors derived inconsistent public keys")
		}
		completionCertificates[output.recipient] = output.completion
	}
	cancel()
	sendWG.Wait()
	return newShares, group, public, completionCertificates, nil
}

func waitCompKeyServiceReady(ctx context.Context, cfg Config, committee []int, service *compKeyService) error {
	need := len(committee) - cfg.F
	if service == nil || need <= 0 {
		return errors.New("invalid CompProve readiness configuration")
	}
	dialTimeout := durationFromEnvMsOr("PRACTICAL_COMPPROVE_READY_DIAL_TIMEOUT_MS", time.Second)
	ioTimeout := durationFromEnvMsOr("PRACTICAL_COMPPROVE_READY_IO_TIMEOUT_MS", 2*time.Second)

	for {
		ready := 0
		remote := make([]int, 0, len(committee))
		for _, id := range committee {
			if service.listeners[id] != nil {
				ready++
			} else {
				remote = append(remote, id)
			}
		}
		if ready >= need {
			return nil
		}

		results := make(chan bool, len(remote))
		for _, id := range remote {
			id := id
			go func() {
				conn, err := dialWithBandwidth("tcp", service.addresses[id], dialTimeout)
				if err != nil {
					results <- false
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(ioTimeout))
				wire := compKeyWire{Kind: "ready", SID: cfg.SID, Epoch: cfg.Epoch, Recipient: id}
				if json.NewEncoder(conn).Encode(wire) != nil {
					results <- false
					return
				}
				var ack compKeyWire
				results <- json.NewDecoder(conn).Decode(&ack) == nil && ack.Kind == "ready-ack" &&
					ack.SID == cfg.SID && ack.Epoch == cfg.Epoch && ack.Recipient == id
			}()
		}
		for range remote {
			select {
			case ok := <-results:
				if ok {
					ready++
					if ready >= need {
						return nil
					}
				}
			case <-ctx.Done():
				return fmt.Errorf("CompProve readiness: reachable=%d need=%d: %w", ready, need, ctx.Err())
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("CompProve readiness: reachable=%d need=%d: %w", ready, need, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveCompKeyWires(ctx context.Context, cfg Config, recipient int, listener net.Listener, out chan<- compKeyWire, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var wire compKeyWire
		if err := json.NewDecoder(conn).Decode(&wire); err == nil {
			if wire.Kind == "ready" && wire.SID == cfg.SID && wire.Epoch == cfg.Epoch && wire.Recipient == recipient {
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_ = json.NewEncoder(conn).Encode(compKeyWire{
					Kind: "ready-ack", SID: cfg.SID, Epoch: cfg.Epoch, Recipient: recipient,
				})
				_ = conn.Close()
				continue
			}
			if wire.Kind != "key" {
				_ = conn.Close()
				continue
			}
			if raw, marshalErr := json.Marshal(&wire); marshalErr == nil {
				recordRecvBytes(len(raw))
			}
			select {
			case out <- wire:
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_ = json.NewEncoder(conn).Encode(compKeyWire{
					Kind: "key-ack", SID: cfg.SID, Epoch: cfg.Epoch,
					Sender: wire.Sender, Recipient: recipient,
				})
			case <-ctx.Done():
			}
		}
		_ = conn.Close()
	}
}

func sendCompKeyWire(ctx context.Context, cfg Config, from, to int, addr string, wire compKeyWire) {
	wire.Recipient = to
	raw, err := json.Marshal(&wire)
	if err != nil {
		return
	}
	timeout := cfg.RouteSendTimeout
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	timeout = durationFromEnvMsOr("PRACTICAL_COMPPROVE_ROUTE_TIMEOUT_MS", timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, dialErr := dialWithBandwidth("tcp", addr, timeout)
		if dialErr == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			written, writeErr := conn.Write(raw)
			recordSentBytes(written)
			var ack compKeyWire
			if writeErr == nil {
				writeErr = json.NewDecoder(conn).Decode(&ack)
			}
			_ = conn.Close()
			if writeErr == nil && ack.Kind == "key-ack" && ack.SID == cfg.SID && ack.Epoch == cfg.Epoch &&
				ack.Sender == wire.Sender && ack.Recipient == to {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func collectCompKeyWires(
	ctx context.Context,
	cfg Config,
	recipient int,
	committee []int,
	selected []int,
	selectedDigest []byte,
	transcripts map[int]*DXTTranscript,
	compPublic map[int][]byte,
	recipientPrivate *ecdsa.PrivateKey,
	recipientPublic *ecdsa.PublicKey,
	addrMap map[int]string,
	threshold int,
	in chan compKeyWire,
	out chan<- compCollectorOutput,
) {
	committeeSet := make(map[int]struct{}, len(committee))
	for _, id := range committee {
		committeeSet[id] = struct{}{}
	}
	valid := make(map[int]CompPublicKeyShare, threshold)
	// Paper good-case variant (Fig. 4d): once the interpolation threshold is
	// met, wait a bounded extra window for KEY messages from the remaining
	// committee members before interpolating. PRACTICAL_DERIVE_WAIT_ALL_MS=0
	// (default) keeps the legacy proceed-at-threshold behavior.
	waitAll := durationFromEnvMsOr("PRACTICAL_DERIVE_WAIT_ALL_MS", 0)
	var waitAllDone <-chan time.Time
	// The wait window overlaps with whatever the channel carries next (other
	// processes start their completion phase as soon as their own collectors
	// finish). Non-KEY traffic read during the window must be handed back so
	// the next collection phase still observes it; without the window the
	// collector exits at threshold before any other traffic can arrive.
	var stashed []compKeyWire
	defer func() {
		for _, wire := range stashed {
			select {
			case in <- wire:
			default:
			}
		}
	}()
collectKeys:
	for {
		if len(valid) >= threshold {
			if waitAll <= 0 {
				break
			}
			if waitAllDone == nil {
				waitAllDone = time.After(waitAll)
			}
		}
		if len(valid) >= len(committee) {
			break
		}
		select {
		case <-ctx.Done():
			ids := make([]int, 0, len(valid))
			for id := range valid {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			out <- compCollectorOutput{recipient: recipient, err: fmt.Errorf("%w: valid=%d ids=%v need=%d", ctx.Err(), len(valid), ids, threshold)}
			return
		case <-waitAllDone:
			break collectKeys
		case wire := <-in:
			if wire.Kind != "key" {
				stashed = append(stashed, wire)
				continue
			}
			if wire.SID != cfg.SID || wire.Epoch != cfg.Epoch || !bytes.Equal(wire.SelectedDigest, selectedDigest) ||
				wire.Sender != wire.Share.NodeID {
				continue
			}
			if _, ok := committeeSet[wire.Sender]; !ok {
				continue
			}
			if _, duplicate := valid[wire.Sender]; duplicate {
				continue
			}
			if !verifyCompPublicKeyShare(
				cfg.SID, cfg.Epoch, wire.Share, selected, selectedDigest,
				transcripts, compPublic[wire.Sender],
			) {
				continue
			}
			valid[wire.Sender] = wire.Share
		}
	}
	// A sender already multicasts each KEY to the complete committee. Do not
	// relay verified keys from every receiver: that turns the paper's O(n^2)
	// KEY exchange into an avoidable O(n^3) forwarding pattern. Sender retries
	// and the persistent service provide the liveness mechanism.
	if len(valid) > threshold {
		ids := make([]int, 0, len(valid))
		for id := range valid {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		selected := make(map[int]CompPublicKeyShare, threshold)
		for _, id := range ids[:threshold] {
			selected[id] = valid[id]
		}
		valid = selected
	}
	group, public, err := interpolateCompPublicKeys(committee, valid, threshold)
	if err != nil {
		out <- compCollectorOutput{recipient: recipient, err: err}
		return
	}
	completion, err := buildCompKeyCompletionCertificate(
		cfg, recipient, selectedDigest, threshold, group, valid, recipientPrivate,
	)
	if err == nil && !verifyCompKeyCompletionCertificate(cfg, completion, recipientPublic) {
		err = errors.New("CompProve completion certificate self-verification failed")
	}
	out <- compCollectorOutput{recipient: recipient, group: group, public: public, completion: completion, err: err}
}

func compPublicKeyShareDigest(share CompPublicKeyShare) ([]byte, error) {
	raw, err := json.Marshal(&share)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-KEY-SHARE-DIGEST-v1"))
	h.Write(raw)
	return h.Sum(nil), nil
}

func compKeyCompletionMessage(cfg Config, certificate CompKeyCompletionCertificate) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-KEY-COMPLETION-v1"))
	writeCoinField(h, []byte(cfg.SID))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], cfg.Epoch)
	h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(certificate.Recipient))
	h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(certificate.Threshold))
	h.Write(number[:])
	writeCoinField(h, certificate.SelectedDigest)
	writeCoinField(h, certificate.GroupPublicKey)
	senders := make([]int, 0, len(certificate.ShareDigests))
	for sender := range certificate.ShareDigests {
		senders = append(senders, sender)
	}
	sort.Ints(senders)
	for _, sender := range senders {
		binary.BigEndian.PutUint64(number[:], uint64(sender))
		h.Write(number[:])
		writeCoinField(h, certificate.ShareDigests[sender])
	}
	return h.Sum(nil)
}

func buildCompKeyCompletionCertificate(
	cfg Config,
	recipient int,
	selectedDigest []byte,
	threshold int,
	group []byte,
	valid map[int]CompPublicKeyShare,
	private *ecdsa.PrivateKey,
) (CompKeyCompletionCertificate, error) {
	if private == nil || len(valid) < threshold {
		return CompKeyCompletionCertificate{}, errors.New("CompProve completion input incomplete")
	}
	ids := make([]int, 0, len(valid))
	for sender := range valid {
		ids = append(ids, sender)
	}
	sort.Ints(ids)
	ids = ids[:threshold]
	certificate := CompKeyCompletionCertificate{
		Recipient: recipient, Threshold: threshold,
		SelectedDigest: append([]byte(nil), selectedDigest...),
		GroupPublicKey: append([]byte(nil), group...),
		ShareDigests:   make(map[int][]byte, threshold),
	}
	for _, sender := range ids {
		share := valid[sender]
		digest, err := compPublicKeyShareDigest(share)
		if err != nil {
			return CompKeyCompletionCertificate{}, err
		}
		certificate.ShareDigests[sender] = digest
	}
	signature, err := ecdsa.SignASN1(rand.Reader, private, compKeyCompletionMessage(cfg, certificate))
	if err != nil {
		return CompKeyCompletionCertificate{}, err
	}
	certificate.Signature = signature
	return certificate, nil
}

func verifyCompKeyCompletionCertificate(cfg Config, certificate CompKeyCompletionCertificate, public *ecdsa.PublicKey) bool {
	if public == nil || certificate.Threshold <= 0 || len(certificate.ShareDigests) != certificate.Threshold ||
		len(certificate.SelectedDigest) != sha256.Size || len(certificate.GroupPublicKey) == 0 || len(certificate.Signature) == 0 {
		return false
	}
	for _, digest := range certificate.ShareDigests {
		if len(digest) != sha256.Size {
			return false
		}
	}
	return ecdsa.VerifyASN1(public, compKeyCompletionMessage(cfg, certificate), certificate.Signature)
}

func samePublicShareMap(left, right map[int][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for id, value := range left {
		if !bytes.Equal(value, right[id]) {
			return false
		}
	}
	return true
}
