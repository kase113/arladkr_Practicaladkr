package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// partialVerifyResultWire is a compact, signed result multicast. It carries
// one bit for the verifier's deterministic responsibility window and a digest
// of the dispersed transcript; receivers derive the window from Verifier.
type partialVerifyResultWire struct {
	Dealer           int    `json:"dealer"`
	Verifier         int    `json:"verifier"`
	TranscriptDigest []byte `json:"transcript_digest"`
	Valid            bool   `json:"valid"`
	Signature        []byte `json:"signature"`
	BatchID          []byte `json:"batch_id,omitempty"`
	BatchIndex       int    `json:"batch_index,omitempty"`
	BatchCount       int    `json:"batch_count,omitempty"`
	BatchSignature   []byte `json:"batch_signature,omitempty"`
}

type partialVerifyBatchEntry struct {
	Dealer           int    `json:"dealer"`
	TranscriptDigest []byte `json:"transcript_digest"`
	Valid            bool   `json:"valid"`
}

type partialVerifyBatchWire struct {
	Kind      string                    `json:"kind"`
	Verifier  int                       `json:"verifier"`
	Entries   []partialVerifyBatchEntry `json:"entries"`
	Signature []byte                    `json:"signature"`
}

func partialVerifyBatchSignatureEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PRACTICAL_PARTIAL_VERIFY_BATCH_SIGNATURE")))
	return raw == "1" || raw == "true" || raw == "yes"
}

func partialVerifyBatchMessage(verifier int, entries []partialVerifyBatchEntry) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-PARTIAL-VERIFY-BATCH-v1"))
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(verifier))
	binary.BigEndian.PutUint64(numbers[8:], uint64(len(entries)))
	h.Write(numbers[:])
	for _, entry := range entries {
		binary.BigEndian.PutUint64(numbers[:8], uint64(entry.Dealer))
		h.Write(numbers[:8])
		h.Write(entry.TranscriptDigest)
		if entry.Valid {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}
	return h.Sum(nil)
}

func partialVerifyBatchID(verifier int, entries []partialVerifyBatchEntry) []byte {
	digest := partialVerifyBatchMessage(verifier, entries)
	return append([]byte(nil), digest...)
}

func partialVerifyTranscriptDigest(transcript *DXTTranscript) ([]byte, error) {
	if transcript == nil {
		return nil, errors.New("nil transcript")
	}
	raw, err := json.Marshal(transcript)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("PRACTICAL-PARTIAL-VERIFY-TRANSCRIPT-v1"))
	h.Write(raw)
	return h.Sum(nil), nil
}

func partialVerifyResultMessage(w *partialVerifyResultWire) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-PARTIAL-VERIFY-RESULT-v1"))
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(w.Dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(w.Verifier))
	h.Write(b[:])
	h.Write(w.TranscriptDigest)
	if w.Valid {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func partialVerifyNetworkTimeout(cfg Config) time.Duration {
	timeout := durationFromEnvMsOr("PRACTICAL_PARTIAL_VERIFY_TIMEOUT_MS", 8*time.Second)
	if cfg.RouteSendTimeout > 0 && 8*cfg.RouteSendTimeout > timeout {
		timeout = 8 * cfg.RouteSendTimeout
	}
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	return timeout
}

const partialVerifyPortOffset = 12000

func partialVerifyNodeAddrMap(cfg Config) (map[int]string, error) {
	if configured := parseNodeAddrMap(cfg.PartialVerifyNodeAddrs); len(configured) > 0 {
		return configured, nil
	}
	base := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	if len(base) == 0 {
		return nil, errors.New("partial verification requires protocol or dedicated listener addresses")
	}
	derived := make(map[int]string, len(base))
	for id, addr := range base {
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("derive partial verification address for node %d: %w", id, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 || port+partialVerifyPortOffset > 65535 {
			return nil, fmt.Errorf("invalid partial verification port for node %d", id)
		}
		derived[id] = net.JoinHostPort(host, strconv.Itoa(port+partialVerifyPortOffset))
	}
	return derived, nil
}

type partialVerifyService struct {
	addresses map[int]string
	channels  map[int]chan partialVerifyResultWire
	listeners map[int]net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

type partialVerifyCountingReader struct {
	reader io.Reader
	read   int
}

func (reader *partialVerifyCountingReader) Read(buffer []byte) (int, error) {
	n, err := reader.reader.Read(buffer)
	reader.read += n
	return n, err
}

func startPartialVerifyService(ctx context.Context, cfg Config, committee []int) (*partialVerifyService, error) {
	addresses, err := partialVerifyNodeAddrMap(cfg)
	if err != nil {
		return nil, err
	}
	local := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	serviceCtx, cancel := context.WithCancel(ctx)
	service := &partialVerifyService{
		addresses: addresses,
		channels:  make(map[int]chan partialVerifyResultWire),
		listeners: make(map[int]net.Listener),
		cancel:    cancel,
	}
	for _, recipient := range committee {
		if _, ok := local[recipient]; !ok {
			continue
		}
		addr := strings.TrimSpace(addresses[recipient])
		_, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || port == "" {
			service.close()
			return nil, fmt.Errorf("partial verification address for node %d is invalid", recipient)
		}
		listener, listenErr := listenRecastWithRetry(ctx, net.JoinHostPort("0.0.0.0", port))
		if listenErr != nil {
			service.close()
			return nil, fmt.Errorf("partial verification listener %d: %w", recipient, listenErr)
		}
		service.listeners[recipient] = listener
		service.channels[recipient] = make(chan partialVerifyResultWire, len(committee)*len(committee)*2)
		service.wg.Add(1)
		go servePartialVerifyResults(serviceCtx, listener, service.channels[recipient], &service.wg)
	}
	if len(service.listeners) == 0 {
		service.close()
		return nil, errors.New("partial verification service has no local new-committee listener")
	}
	return service, nil
}

func servePartialVerifyResults(
	ctx context.Context,
	listener net.Listener,
	out chan<- partialVerifyResultWire,
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
		counted := &partialVerifyCountingReader{reader: conn}
		decoder := json.NewDecoder(counted)
		for {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				break
			}
			var kind struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(raw, &kind) != nil {
				continue
			}
			if kind.Kind == "partial-verify-batch" {
				var batch partialVerifyBatchWire
				if json.Unmarshal(raw, &batch) != nil || batch.Verifier < 0 || len(batch.Entries) == 0 || len(batch.Signature) == 0 {
					continue
				}
				batchID := partialVerifyBatchID(batch.Verifier, batch.Entries)
				for index, entry := range batch.Entries {
					wire := partialVerifyResultWire{
						Dealer: entry.Dealer, Verifier: batch.Verifier, TranscriptDigest: entry.TranscriptDigest,
						Valid: entry.Valid, BatchID: batchID, BatchIndex: index, BatchCount: len(batch.Entries),
					}
					if index == 0 {
						wire.BatchSignature = append([]byte(nil), batch.Signature...)
					}
					select {
					case out <- wire:
					case <-ctx.Done():
						_ = conn.Close()
						recordRecvBytes(counted.read)
						return
					}
				}
				continue
			}
			var wire partialVerifyResultWire
			if json.Unmarshal(raw, &wire) != nil {
				continue
			}
			select {
			case out <- wire:
			case <-ctx.Done():
				_ = conn.Close()
				recordRecvBytes(counted.read)
				return
			}
		}
		recordRecvBytes(counted.read)
		_ = conn.Close()
	}
}

func (service *partialVerifyService) close() {
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

// runPartialVerificationMulticast distributes lane-local verification results
// and accepts a transcript only after every lane has f+1 signed positive votes.
// The f+1 threshold is sufficient because each lane is assigned to 2f+1
// verifiers and at least f+1 of those verifiers are honest.
func runPartialVerificationMulticast(
	ctx context.Context,
	cfg Config,
	verifiers []int,
	selectedIDs []int,
	transcripts map[int]*DXTTranscript,
	service *partialVerifyService,
	dxt *DXTBackend,
	tracef func(string, ...any),
) ([]int, map[string]int, error) {
	if len(selectedIDs) == 0 {
		return nil, nil, nil
	}
	if service == nil {
		return nil, nil, errors.New("partial verification persistent service is unavailable")
	}
	addrMap := service.addresses
	configuredLocal := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	localIDs := make([]int, 0, len(configuredLocal))
	verifierSet := make(map[int]struct{}, len(verifiers))
	responsibilityByVerifier := make(map[int][]int, len(verifiers))
	for _, id := range verifiers {
		verifierSet[id] = struct{}{}
		lanes, ok := dxt.partialLaneIDs(id)
		if !ok {
			return nil, nil, fmt.Errorf("partial verification verifier %d has no responsibility window", id)
		}
		lanes = append([]int(nil), lanes...)
		responsibilityByVerifier[id] = lanes
		if _, ok := configuredLocal[id]; ok && service.channels[id] != nil {
			localIDs = append(localIDs, id)
		}
	}
	sort.Ints(localIDs)
	if len(addrMap) == 0 || len(localIDs) == 0 {
		return nil, nil, errors.New("partial verification multicast requires protocol transport and a local new-committee verifier")
	}
	coverage := make(map[int]int, len(dxt.newCommittee))
	for _, verifier := range verifiers {
		lanes := responsibilityByVerifier[verifier]
		seenLanes := make(map[int]struct{}, len(lanes))
		for _, rid := range lanes {
			if _, duplicate := seenLanes[rid]; duplicate {
				continue
			}
			seenLanes[rid] = struct{}{}
			coverage[rid]++
		}
	}
	for _, rid := range dxt.newCommittee {
		if coverage[rid] < 2*dxt.f+1 {
			return nil, nil, fmt.Errorf("partial verification lane %d coverage=%d need=%d", rid, coverage[rid], 2*dxt.f+1)
		}
	}
	for _, id := range verifiers {
		if strings.TrimSpace(addrMap[id]) == "" {
			return nil, nil, fmt.Errorf("partial verification missing address for verifier %d", id)
		}
	}

	stageCtx, cancel := context.WithTimeout(ctx, partialVerifyNetworkTimeout(cfg))
	wireCh := make(chan partialVerifyResultWire, len(verifiers)*len(selectedIDs)*2)
	var relayWG sync.WaitGroup
	for _, verifier := range localIDs {
		source := service.channels[verifier]
		relayWG.Add(1)
		go func(in <-chan partialVerifyResultWire) {
			defer relayWG.Done()
			for {
				select {
				case wire := <-in:
					select {
					case wireCh <- wire:
					case <-stageCtx.Done():
						return
					}
				case <-stageCtx.Done():
					return
				}
			}
		}(source)
	}
	defer func() {
		cancel()
		relayWG.Wait()
	}()

	transcriptDigests := make(map[int][]byte, len(selectedIDs))
	transcriptStaticValid := make(map[int]bool, len(selectedIDs))
	for _, dealer := range selectedIDs {
		transcript := transcripts[dealer]
		transcriptStaticValid[dealer] = transcript != nil && dxt.validateTranscriptShape(transcript) &&
			verifyCommitmentDegree(dxt.curve, transcript.Commitments, dxt.newCommittee, dxt.sharingDegree)
		digest, err := partialVerifyTranscriptDigest(transcripts[dealer])
		if err != nil {
			return nil, nil, fmt.Errorf("digest selected transcript %d: %w", dealer, err)
		}
		transcriptDigests[dealer] = digest
	}

	positive := make(map[int]map[int]int, len(selectedIDs))
	seen := make(map[int]map[int]struct{}, len(selectedIDs))
	for _, dealer := range selectedIDs {
		positive[dealer] = make(map[int]int, len(dxt.newCommittee))
		seen[dealer] = make(map[int]struct{}, len(verifiers))
	}
	acceptSingle := func(wire partialVerifyResultWire, verifySignature bool) {
		if _, ok := verifierSet[wire.Verifier]; !ok {
			return
		}
		if _, ok := positive[wire.Dealer]; !ok {
			return
		}
		if !bytesEqual(wire.TranscriptDigest, transcriptDigests[wire.Dealer]) {
			return
		}
		pub := dxt.recipientSignPub[wire.Verifier]
		if verifySignature && (pub == nil || !ecdsa.VerifyASN1(pub, partialVerifyResultMessage(&wire), wire.Signature)) {
			return
		}
		expected, ok := responsibilityByVerifier[wire.Verifier]
		if !ok {
			return
		}
		if _, duplicate := seen[wire.Dealer][wire.Verifier]; duplicate {
			return
		}
		seen[wire.Dealer][wire.Verifier] = struct{}{}
		for _, rid := range expected {
			if wire.Valid {
				positive[wire.Dealer][rid]++
			}
		}
	}
	type batchState struct {
		entries   map[int]partialVerifyResultWire
		signature []byte
	}
	batchStates := make(map[string]*batchState, len(verifiers))
	completedBatches := make(map[string]struct{}, len(verifiers))
	accept := func(wire partialVerifyResultWire) {
		if wire.BatchCount <= 0 {
			acceptSingle(wire, true)
			return
		}
		if !partialVerifyBatchSignatureEnabled() || wire.BatchCount != len(selectedIDs) ||
			wire.BatchIndex < 0 || wire.BatchIndex >= wire.BatchCount || len(wire.BatchID) == 0 ||
			wire.Signature != nil {
			return
		}
		if _, ok := verifierSet[wire.Verifier]; !ok {
			return
		}
		key := fmt.Sprintf("%d:%x", wire.Verifier, wire.BatchID)
		if _, done := completedBatches[key]; done {
			return
		}
		state := batchStates[key]
		if state == nil {
			if len(batchStates) >= len(verifiers)*2+8 {
				return
			}
			state = &batchState{entries: make(map[int]partialVerifyResultWire, wire.BatchCount)}
			batchStates[key] = state
		}
		if len(wire.BatchSignature) > 0 {
			if len(state.signature) > 0 && !bytesEqual(state.signature, wire.BatchSignature) {
				delete(batchStates, key)
				return
			}
			state.signature = append([]byte(nil), wire.BatchSignature...)
		}
		if previous, exists := state.entries[wire.BatchIndex]; exists {
			if previous.Dealer != wire.Dealer || !bytesEqual(previous.TranscriptDigest, wire.TranscriptDigest) || previous.Valid != wire.Valid {
				delete(batchStates, key)
			}
			return
		}
		state.entries[wire.BatchIndex] = wire
		if len(state.entries) != wire.BatchCount || len(state.signature) == 0 {
			return
		}
		entries := make([]partialVerifyBatchEntry, wire.BatchCount)
		ordered := make([]partialVerifyResultWire, wire.BatchCount)
		for index := range ordered {
			entry, exists := state.entries[index]
			if !exists || entry.BatchCount != wire.BatchCount || entry.BatchIndex != index {
				return
			}
			if index >= len(selectedIDs) || entry.Dealer != selectedIDs[index] ||
				!bytesEqual(entry.TranscriptDigest, transcriptDigests[entry.Dealer]) {
				delete(batchStates, key)
				return
			}
			ordered[index] = entry
			entries[index] = partialVerifyBatchEntry{Dealer: entry.Dealer, TranscriptDigest: entry.TranscriptDigest, Valid: entry.Valid}
		}
		pub := dxt.recipientSignPub[wire.Verifier]
		if pub == nil || !bytesEqual(partialVerifyBatchID(wire.Verifier, entries), wire.BatchID) ||
			!ecdsa.VerifyASN1(pub, partialVerifyBatchMessage(wire.Verifier, entries), state.signature) {
			delete(batchStates, key)
			return
		}
		completedBatches[key] = struct{}{}
		delete(batchStates, key)
		for _, entry := range ordered {
			acceptSingle(entry, false)
		}
	}

	prepared := make(map[int][]byte, len(localIDs))
	batchSignatureMode := partialVerifyBatchSignatureEnabled()
	for _, verifier := range localIDs {
		if dxt.recipientSignPriv[verifier] == nil {
			return nil, nil, fmt.Errorf("partial verification local signer %d key unavailable", verifier)
		}
		batch := make([]byte, 0, len(selectedIDs)*256)
		wires := make([]partialVerifyResultWire, 0, len(selectedIDs))
		entries := make([]partialVerifyBatchEntry, 0, len(selectedIDs))
		for _, dealer := range selectedIDs {
			lanes, ok := map[int]bool(nil), false
			if transcriptStaticValid[dealer] {
				lanes, ok = dxt.partialVerifyLanesPrevalidated(verifier, transcripts[dealer])
			}
			expected, expectedOK := responsibilityByVerifier[verifier]
			allValid := ok && expectedOK && len(lanes) == len(expected)
			for _, rid := range expected {
				if !lanes[rid] {
					allValid = false
					break
				}
			}
			wire := partialVerifyResultWire{Dealer: dealer, Verifier: verifier, TranscriptDigest: transcriptDigests[dealer], Valid: allValid}
			wires = append(wires, wire)
			entries = append(entries, partialVerifyBatchEntry{Dealer: dealer, TranscriptDigest: transcriptDigests[dealer], Valid: allValid})
		}
		if batchSignatureMode {
			message := partialVerifyBatchMessage(verifier, entries)
			signature, err := ecdsa.SignASN1(rand.Reader, dxt.recipientSignPriv[verifier], message)
			if err != nil {
				return nil, nil, err
			}
			batchID := partialVerifyBatchID(verifier, entries)
			for index := range wires {
				wires[index].BatchID = batchID
				wires[index].BatchIndex = index
				wires[index].BatchCount = len(wires)
				if index == 0 {
					wires[index].BatchSignature = signature
				}
			}
		}
		if batchSignatureMode {
			raw, err := json.Marshal(partialVerifyBatchWire{
				Kind: "partial-verify-batch", Verifier: verifier, Entries: entries,
				Signature: wires[0].BatchSignature,
			})
			if err != nil {
				return nil, nil, err
			}
			batch = append(batch, raw...)
			batch = append(batch, '\n')
		}
		for _, wire := range wires {
			if !batchSignatureMode {
				var err error
				wire.Signature, err = ecdsa.SignASN1(rand.Reader, dxt.recipientSignPriv[verifier], partialVerifyResultMessage(&wire))
				if err != nil {
					return nil, nil, err
				}
			}
			if !batchSignatureMode {
				raw, err := json.Marshal(wire)
				if err != nil {
					return nil, nil, err
				}
				batch = append(batch, raw...)
				batch = append(batch, '\n')
			}
			// A local verifier's result is trusted only after the same signature
			// and batch/lane checks used for received multicast messages.
			accept(wire)
		}
		prepared[verifier] = batch
	}

	var sendWG sync.WaitGroup
	for _, verifier := range localIDs {
		body := prepared[verifier]
		for _, target := range verifiers {
			if target == verifier {
				continue
			}
			targetAddr := addrMap[target]
			sendWG.Add(1)
			go func(addr string, batch []byte) {
				defer sendWG.Done()
				for {
					select {
					case <-stageCtx.Done():
						return
					default:
					}
					conn, dialErr := dialWithBandwidth("tcp", addr, 500*time.Millisecond)
					if dialErr == nil {
						_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
						remaining := batch
						var writeErr error
						for len(remaining) > 0 {
							var written int
							written, writeErr = conn.Write(remaining)
							recordSentBytes(written)
							remaining = remaining[written:]
							if writeErr != nil || written == 0 {
								break
							}
						}
						_ = conn.Close()
						if writeErr == nil && len(remaining) == 0 {
							return
						}
					}
					select {
					case <-stageCtx.Done():
						return
					case <-time.After(40 * time.Millisecond):
					}
				}
			}(targetAddr, body)
		}
	}

	complete := func() bool {
		need := dxt.f + 1
		for _, dealer := range selectedIDs {
			for _, rid := range dxt.newCommittee {
				if positive[dealer][rid] < need {
					return false
				}
			}
		}
		return true
	}
	for !complete() {
		select {
		case wire := <-wireCh:
			accept(wire)
		case <-stageCtx.Done():
			sendWG.Wait()
			return nil, nil, fmt.Errorf("partial verification result multicast timeout")
		}
	}
	// In local multi-node simulation all old verifiers are hosted by one
	// process, so direct local votes can satisfy the threshold before the
	// multicast writes finish.  Drain those writes to keep communication
	// measurements representative; distributed processes do not take this
	// path and retain the threshold-first latency behavior.
	if len(localIDs) == len(verifiers) {
		sendWG.Wait()
	}
	cancel()
	sendWG.Wait()
	positiveVotes := make(map[string]int, len(selectedIDs)*len(dxt.newCommittee))
	for _, dealer := range selectedIDs {
		for _, rid := range dxt.newCommittee {
			key := fmt.Sprintf("%d/%d", dealer, rid)
			positiveVotes[key] = positive[dealer][rid]
			tracef("phase=partial_verify_lane_votes dealer=%d lane=%d positive=%d", dealer, rid, positive[dealer][rid])
		}
	}
	tracef("phase=partial_verify_multicast_end transcripts=%d threshold=%d", len(selectedIDs), dxt.f+1)
	return append([]int(nil), selectedIDs...), positiveVotes, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
