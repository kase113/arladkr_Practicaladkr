package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dmvba "dumbomvba_go/core"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const thresholdCoinBLSDomain = "PRACTICAL_ADKR_THRESHOLD_COIN_V2"

type thresholdCoinShareWire struct {
	Kind      string `json:"kind"`
	SID       string `json:"sid"`
	Epoch     uint64 `json:"epoch"`
	Signer    int    `json:"signer"`
	Index     int    `json:"index"`
	Recipient int    `json:"recipient"`
	Digest    []byte `json:"digest"`
	Share     []byte `json:"share"`
}

type thresholdCoinOutput struct {
	recipient int
	signature []byte
	err       error
}

type thresholdCoinService struct {
	cfg       Config
	addresses map[int]string
	channels  map[int]chan thresholdCoinShareWire
	listeners map[int]net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func thresholdCoinAddresses(cfg Config, committee []int) (map[int]string, error) {
	if configured := parseNodeAddrMap(cfg.CoinNodeAddrs); len(configured) > 0 {
		for _, id := range committee {
			if strings.TrimSpace(configured[id]) == "" {
				return nil, fmt.Errorf("threshold coin address missing for node %d", id)
			}
		}
		return configured, nil
	}
	protocol := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	derived := make(map[int]string, len(committee))
	for _, id := range committee {
		host, portText, err := net.SplitHostPort(protocol[id])
		if err != nil {
			return nil, fmt.Errorf("derive threshold coin address for node %d: %w", id, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port+20000 > 65535 {
			return nil, fmt.Errorf("invalid derived threshold coin port for node %d", id)
		}
		derived[id] = net.JoinHostPort(host, strconv.Itoa(port+20000))
	}
	return derived, nil
}

func startThresholdCoinService(ctx context.Context, cfg Config, committee []int, localPrivate map[int]fr.Element) (*thresholdCoinService, error) {
	addresses, err := thresholdCoinAddresses(cfg, committee)
	if err != nil {
		return nil, err
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	service := &thresholdCoinService{
		cfg: cfg, addresses: addresses, channels: make(map[int]chan thresholdCoinShareWire),
		listeners: make(map[int]net.Listener), cancel: cancel,
	}
	for _, recipient := range committee {
		if _, ok := localPrivate[recipient]; !ok {
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
			return nil, fmt.Errorf("listen persistent threshold coin node %d: %w", recipient, listenErr)
		}
		service.listeners[recipient] = listener
		service.channels[recipient] = make(chan thresholdCoinShareWire, len(committee)*2)
		service.wg.Add(1)
		go serveThresholdCoinShares(serviceCtx, cfg, recipient, listener, service.channels[recipient], &service.wg)
	}
	if len(service.listeners) == 0 {
		service.close()
		return nil, fmt.Errorf("threshold coin service has no local listener")
	}
	return service, nil
}

func (service *thresholdCoinService) close() {
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

func runThresholdCoin(
	ctx context.Context,
	cfg Config,
	old []int,
	decided []int,
	kappa int,
	keys *thresholdCoinKeySet,
	service *thresholdCoinService,
) ([]int, []byte, error) {
	digest, err := thresholdCoinInputDigest(cfg.SID, cfg.Epoch, old, decided)
	if err != nil {
		return nil, nil, err
	}
	if keys == nil || keys.threshold != len(old)-cfg.F || keys.lowThreshold != cfg.F+1 || len(keys.nodeIDs) != len(old) {
		return nil, nil, fmt.Errorf("threshold coin key/config mismatch")
	}
	for i := range old {
		if keys.nodeIDs[i] != old[i] {
			return nil, nil, fmt.Errorf("threshold coin committee mismatch")
		}
	}

	if !cfg.StrictNetwork && len(keys.privateShare) == len(old) {
		signature, recoverErr := recoverThresholdCoinLocally(keys, digest)
		if recoverErr != nil {
			return nil, nil, recoverErr
		}
		selected, selectErr := selectByThresholdCoin(decided, kappa, signature, digest)
		return selected, signature, selectErr
	}

	if service == nil {
		return nil, nil, fmt.Errorf("threshold Coin.Get persistent service unavailable")
	}
	addrMap := service.addresses
	if len(addrMap) < len(old) {
		return nil, nil, fmt.Errorf("threshold Coin.Get requires all old-committee protocol addresses")
	}
	localIDs := make([]int, 0, len(keys.privateShare))
	for _, id := range old {
		if _, ok := keys.privateShare[id]; ok {
			localIDs = append(localIDs, id)
		}
	}
	if len(localIDs) == 0 {
		return nil, nil, fmt.Errorf("threshold Coin.Get has no local signing identity")
	}

	coinCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, recipient := range localIDs {
		if service.channels[recipient] == nil || service.listeners[recipient] == nil {
			return nil, nil, fmt.Errorf("threshold Coin.Get service missing local node %d", recipient)
		}
	}

	outputs := make(chan thresholdCoinOutput, len(localIDs))
	for _, recipient := range localIDs {
		recipient := recipient
		go collectThresholdCoinShares(coinCtx, cfg, recipient, digest, keys, service.channels[recipient], outputs)
	}

	var sendWG sync.WaitGroup
	for _, signerID := range localIDs {
		signer, signerErr := keys.signer(signerID)
		if signerErr != nil {
			return nil, nil, signerErr
		}
		share, signErr := signer.Sign(thresholdCoinBLSDomain, digest)
		if signErr != nil {
			return nil, nil, signErr
		}
		for _, recipient := range old {
			wire := thresholdCoinShareWire{
				Kind:      "share",
				SID:       cfg.SID,
				Epoch:     cfg.Epoch,
				Signer:    signerID,
				Index:     keys.nodeIndex[signerID],
				Recipient: recipient,
				Digest:    append([]byte(nil), digest...),
				Share:     append([]byte(nil), share...),
			}
			if localCh, ok := service.channels[recipient]; ok {
				localCh <- wire
				continue
			}
			sendWG.Add(1)
			go func(from, to int, target string, message thresholdCoinShareWire) {
				defer sendWG.Done()
				sendThresholdCoinShare(coinCtx, cfg, from, to, target, message)
			}(signerID, recipient, addrMap[recipient], wire)
		}
	}

	var recovered []byte
	for range localIDs {
		select {
		case <-ctx.Done():
			cancel()
			sendWG.Wait()
			return nil, nil, ctx.Err()
		case output := <-outputs:
			if output.err != nil {
				cancel()
				sendWG.Wait()
				return nil, nil, fmt.Errorf("threshold coin recipient %d: %w", output.recipient, output.err)
			}
			if recovered == nil {
				recovered = append([]byte(nil), output.signature...)
			} else if !bytes.Equal(recovered, output.signature) {
				cancel()
				sendWG.Wait()
				return nil, nil, fmt.Errorf("threshold coin produced inconsistent recovered signatures")
			}
		}
	}
	sendsDone := make(chan struct{})
	go func() {
		sendWG.Wait()
		close(sendsDone)
	}()
	select {
	case <-sendsDone:
	case <-time.After(durationFromEnvMsOr("PRACTICAL_COIN_DELIVERY_GRACE_MS", time.Second)):
	}
	cancel()
	<-sendsDone
	selected, err := selectByThresholdCoin(decided, kappa, recovered, digest)
	if err != nil {
		return nil, nil, err
	}
	return selected, recovered, nil
}

func (keys *thresholdCoinKeySet) signer(nodeID int) (dmvba.ThresholdSigner, error) {
	index, ok := keys.nodeIndex[nodeID]
	if !ok {
		return nil, fmt.Errorf("threshold coin node %d has no committee index", nodeID)
	}
	share, ok := keys.privateShare[nodeID]
	if !ok {
		return nil, fmt.Errorf("threshold coin node %d has no private share", nodeID)
	}
	high := dmvba.NewBLS12381Signer(
		index,
		share,
		keys.groupPublic,
		keys.sharePublic,
		len(keys.nodeIDs),
		keys.threshold,
	)
	lowShare, ok := keys.lowPrivateShare[nodeID]
	if !ok {
		return nil, fmt.Errorf("threshold coin node %d has no low-threshold private share", nodeID)
	}
	low := dmvba.NewBLS12381Signer(
		index, lowShare, keys.lowGroupPublic, keys.lowSharePublic,
		len(keys.nodeIDs), keys.lowThreshold,
	)
	return &dualThresholdSigner{high: high, low: low}, nil
}

type dualThresholdSigner struct {
	high dmvba.ThresholdSigner
	low  dmvba.ThresholdSigner
}

func (s *dualThresholdSigner) ID() int { return s.high.ID() }

func (s *dualThresholdSigner) selectSigner(domain string) dmvba.ThresholdSigner {
	switch strings.ToUpper(strings.TrimSpace(domain)) {
	case "PD_STORED", "PD_LOCKED", apdbThresholdDomain:
		return s.high
	default:
		return s.low
	}
}

func (s *dualThresholdSigner) Threshold(domain string) int {
	return s.selectSigner(domain).Threshold(domain)
}
func (s *dualThresholdSigner) Sign(domain string, digest []byte) ([]byte, error) {
	return s.selectSigner(domain).Sign(domain, digest)
}
func (s *dualThresholdSigner) Verify(from int, domain string, digest, sig []byte) bool {
	return s.selectSigner(domain).Verify(from, domain, digest, sig)
}
func (s *dualThresholdSigner) Recover(domain string, digest []byte, shares map[int][]byte) ([]byte, error) {
	return s.selectSigner(domain).Recover(domain, digest, shares)
}
func (s *dualThresholdSigner) VerifyRecovered(domain string, digest, sig []byte) bool {
	return s.selectSigner(domain).VerifyRecovered(domain, digest, sig)
}

func recoverThresholdCoinLocally(keys *thresholdCoinKeySet, digest []byte) ([]byte, error) {
	shares := make(map[int][]byte, keys.lowThreshold)
	var combiner dmvba.ThresholdSigner
	for _, nodeID := range keys.nodeIDs {
		signer, err := keys.signer(nodeID)
		if err != nil {
			return nil, err
		}
		if combiner == nil {
			combiner = signer
		}
		share, err := signer.Sign(thresholdCoinBLSDomain, digest)
		if err != nil {
			return nil, err
		}
		index := keys.nodeIndex[nodeID]
		if !combiner.Verify(index, thresholdCoinBLSDomain, digest, share) {
			return nil, fmt.Errorf("locally generated threshold coin share failed verification")
		}
		shares[index] = share
		if len(shares) == keys.lowThreshold {
			break
		}
	}
	if combiner == nil || len(shares) < keys.lowThreshold {
		return nil, fmt.Errorf("insufficient local threshold coin shares")
	}
	recovered, err := combiner.Recover(thresholdCoinBLSDomain, digest, shares)
	if err != nil {
		return nil, err
	}
	if !combiner.VerifyRecovered(thresholdCoinBLSDomain, digest, recovered) {
		return nil, fmt.Errorf("recovered threshold coin signature failed verification")
	}
	return recovered, nil
}

func collectThresholdCoinShares(
	ctx context.Context,
	cfg Config,
	recipient int,
	digest []byte,
	keys *thresholdCoinKeySet,
	in <-chan thresholdCoinShareWire,
	out chan<- thresholdCoinOutput,
) {
	combiner, err := keys.signer(recipient)
	if err != nil {
		out <- thresholdCoinOutput{recipient: recipient, err: err}
		return
	}
	shares := make(map[int][]byte, keys.lowThreshold)
	for len(shares) < keys.lowThreshold {
		select {
		case <-ctx.Done():
			out <- thresholdCoinOutput{recipient: recipient, err: ctx.Err()}
			return
		case wire := <-in:
			index, ok := keys.nodeIndex[wire.Signer]
			if !ok || wire.Index != index || wire.Recipient != recipient || wire.SID != cfg.SID ||
				wire.Epoch != cfg.Epoch || !bytes.Equal(wire.Digest, digest) {
				continue
			}
			if _, duplicate := shares[index]; duplicate {
				continue
			}
			if !combiner.Verify(index, thresholdCoinBLSDomain, digest, wire.Share) {
				continue
			}
			shares[index] = append([]byte(nil), wire.Share...)
		}
	}
	recovered, err := combiner.Recover(thresholdCoinBLSDomain, digest, shares)
	if err == nil && !combiner.VerifyRecovered(thresholdCoinBLSDomain, digest, recovered) {
		err = fmt.Errorf("recovered threshold coin signature failed verification")
	}
	out <- thresholdCoinOutput{recipient: recipient, signature: recovered, err: err}
}

func serveThresholdCoinShares(
	ctx context.Context,
	cfg Config,
	recipient int,
	listener net.Listener,
	out chan<- thresholdCoinShareWire,
	wg *sync.WaitGroup,
) {
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
		var wire thresholdCoinShareWire
		if err := json.NewDecoder(conn).Decode(&wire); err == nil && wire.Kind == "share" &&
			wire.SID == cfg.SID && wire.Epoch == cfg.Epoch && wire.Recipient == recipient {
			if raw, marshalErr := json.Marshal(&wire); marshalErr == nil {
				recordRecvBytes(len(raw))
			}
			select {
			case out <- wire:
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_ = json.NewEncoder(conn).Encode(thresholdCoinShareWire{
					Kind: "share-ack", SID: cfg.SID, Epoch: cfg.Epoch,
					Signer: wire.Signer, Recipient: recipient,
				})
			case <-ctx.Done():
			}
		}
		_ = conn.Close()
	}
}

func sendThresholdCoinShare(ctx context.Context, cfg Config, from, to int, addr string, wire thresholdCoinShareWire) {
	raw, err := json.Marshal(&wire)
	if err != nil {
		return
	}
	timeout := cfg.RouteSendTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, dialErr := dialWithBandwidth("tcp", addr, timeout)
		if dialErr == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			written, writeErr := conn.Write(raw)
			recordSentBytes(written)
			var ack thresholdCoinShareWire
			if writeErr == nil {
				writeErr = json.NewDecoder(conn).Decode(&ack)
			}
			_ = conn.Close()
			if writeErr == nil && ack.Kind == "share-ack" && ack.SID == cfg.SID && ack.Epoch == cfg.Epoch &&
				ack.Signer == wire.Signer && ack.Recipient == to {
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

func thresholdCoinInputDigest(sid string, epoch uint64, old, decided []int) ([]byte, error) {
	if strings.TrimSpace(sid) == "" || len(decided) == 0 {
		return nil, fmt.Errorf("threshold coin input requires SID and decided set")
	}
	committee := make(map[int]struct{}, len(old))
	for _, id := range old {
		committee[id] = struct{}{}
	}
	canonical := append([]int(nil), decided...)
	sort.Ints(canonical)
	h := sha256.New()
	h.Write([]byte("PADKR-THRESHOLD-COIN-INPUT-V2"))
	writeCoinField(h, []byte(sid))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], epoch)
	h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(len(canonical)))
	h.Write(number[:])
	for i, id := range canonical {
		if _, ok := committee[id]; !ok {
			return nil, fmt.Errorf("threshold coin decided dealer %d is outside old committee", id)
		}
		if i > 0 && canonical[i-1] == id {
			return nil, fmt.Errorf("threshold coin decided set contains duplicate dealer %d", id)
		}
		binary.BigEndian.PutUint64(number[:], uint64(id))
		h.Write(number[:])
	}
	return h.Sum(nil), nil
}

func writeCoinField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}
