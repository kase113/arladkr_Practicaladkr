package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

type mvbaABAVoteMsg struct {
	Round   int
	Node    int
	Bit     int
	Payload []byte
}

type mvbaABACoinMsg struct {
	Round int
	Node  int
	Share []byte
}

type DumboMVBA struct {
	cfg       Config
	net       Network
	signer    Signer
	spbc      SPBCDriver
	recv      <-chan ReceivedMessage
	logger    Logger
	rcStoreMu sync.RWMutex
	rcStores  map[string]rcStoreMsg
}

func NewDumboMVBA(
	cfg Config,
	net Network,
	signer Signer,
	spbc SPBCDriver,
	recv <-chan ReceivedMessage,
	logger Logger,
) (*DumboMVBA, error) {
	if cfg.SID == "" || cfg.N <= 0 || cfg.F < 0 || cfg.N < 3*cfg.F+1 {
		return nil, fmt.Errorf("%w: sid/n/f", ErrInvalidConfig)
	}
	if cfg.ID < 0 || cfg.ID >= cfg.N {
		return nil, fmt.Errorf("%w: id out of range", ErrInvalidConfig)
	}
	if cfg.MaxRounds <= 0 {
		cfg.MaxRounds = 1
	}
	if cfg.WaitSPBCTimeout <= 0 {
		cfg.WaitSPBCTimeout = 2 * time.Second
	}
	if cfg.RouteSendTimeout <= 0 {
		cfg.RouteSendTimeout = 300 * time.Millisecond
	}
	if net == nil {
		return nil, fmt.Errorf("%w: nil network", ErrInvalidConfig)
	}
	if !cfg.UseEquivalentPath && spbc == nil {
		return nil, fmt.Errorf("%w: nil spbc driver", ErrInvalidConfig)
	}
	if recv == nil {
		return nil, fmt.Errorf("%w: nil receive channel", ErrInvalidConfig)
	}
	if cfg.UseEquivalentPath {
		thresholdSigner, ok := signer.(ThresholdSigner)
		if !ok || thresholdSigner.Threshold("PD_STORED") != cfg.N-cfg.F ||
			thresholdSigner.Threshold("PD_LOCKED") != cfg.N-cfg.F ||
			thresholdSigner.Threshold("PD_QUIT_READY") != cfg.F+1 ||
			thresholdSigner.Threshold("EQ_COIN_SHARE") != cfg.F+1 {
			return nil, fmt.Errorf("%w: invalid threshold signer for equivalent path", ErrInvalidConfig)
		}
	}
	if cfg.EquivalentCoinMode == "" {
		cfg.EquivalentCoinMode = "signature"
	}

	return &DumboMVBA{
		cfg:      cfg,
		net:      net,
		signer:   signer,
		spbc:     spbc,
		recv:     recv,
		logger:   logger,
		rcStores: make(map[string]rcStoreMsg),
	}, nil
}

func (m *DumboMVBA) cacheRCStore(store *rcStoreMsg) {
	if m == nil || store == nil || store.SID == "" {
		return
	}
	cp := rcStoreMsg{
		SID: store.SID, Root: append([]byte(nil), store.Root...), From: store.From,
		Stripe: append([]byte(nil), store.Stripe...),
		Branch: merkleBranch{Index: store.Branch.Index, Siblings: cloneSiblings(store.Branch.Siblings)},
	}
	m.rcStoreMu.Lock()
	if m.rcStores == nil {
		m.rcStores = make(map[string]rcStoreMsg)
	}
	m.rcStores[store.SID] = cp
	m.rcStoreMu.Unlock()
}

func (m *DumboMVBA) cachedRCStore(sid string) (*rcStoreMsg, bool) {
	if m == nil || sid == "" {
		return nil, false
	}
	m.rcStoreMu.RLock()
	store, ok := m.rcStores[sid]
	m.rcStoreMu.RUnlock()
	if !ok {
		return nil, false
	}
	cp := store
	cp.Root = append([]byte(nil), store.Root...)
	cp.Stripe = append([]byte(nil), store.Stripe...)
	cp.Branch.Siblings = cloneSiblings(store.Branch.Siblings)
	return &cp, true
}

func (m *DumboMVBA) Run(ctx context.Context, input ProposalValue) (ProposalValue, error) {
	if !m.payloadValid(input.Payload) {
		return ProposalValue{}, fmt.Errorf("mvba local input rejected by payload predicate")
	}
	if m.cfg.UseEquivalentPath {
		out, err := m.runEquivalent(ctx, input)
		if err != nil {
			return ProposalValue{}, err
		}
		if !m.payloadValid(out.Payload) {
			return ProposalValue{}, fmt.Errorf("mvba decided payload rejected by payload predicate")
		}
		return out, nil
	}

	var lastErr error

	for round := 0; round < m.cfg.MaxRounds; round++ {
		leader := leaderOrder(m.cfg.SID, m.cfg.N, round)[0]
		runInput := roundLeaderInput(m.cfg.ID, leader, input)

		roundCtx, cancel := context.WithTimeout(ctx, m.cfg.WaitSPBCTimeout)
		handle, err := m.spbc.Start(roundCtx, m.cfg.SID, m.cfg.ID, m.cfg.N, m.cfg.F, round, leader, runInput)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("start spbc round %d leader %d: %w", round, leader, err)
			continue
		}
		if handle.Close == nil {
			handle.Close = func() {}
		}
		decided, ok, runErr := m.runRound(roundCtx, round, leader, handle)
		handle.Close()
		if m.signer == nil {
			if runErr != nil {
				cancel()
				lastErr = runErr
				continue
			}
			cancel()
			if ok {
				if !m.payloadValid(decided.Payload) {
					return ProposalValue{}, fmt.Errorf("mvba decided payload rejected by payload predicate")
				}
				return decided, nil
			}
			lastErr = fmt.Errorf("round %d finished without decision", round)
			continue
		}

		cancel()
		abaCtx, abaCancel := context.WithTimeout(ctx, m.cfg.WaitSPBCTimeout)
		if runErr != nil {
			ok = false
			decided = ProposalValue{}
		}
		accepted, out, abaErr := m.runCoinABA(abaCtx, round, ok, decided)
		abaCancel()
		if abaErr != nil {
			if ok {
				// Preserve liveness in experimental settings when ABA exchange is delayed.
				if !m.payloadValid(decided.Payload) {
					return ProposalValue{}, fmt.Errorf("mvba decided payload rejected by payload predicate")
				}
				return decided, nil
			}
			if runErr != nil {
				lastErr = fmt.Errorf("%v; %w", runErr, abaErr)
			} else {
				lastErr = abaErr
			}
			continue
		}
		if accepted {
			if !m.payloadValid(out.Payload) {
				return ProposalValue{}, fmt.Errorf("mvba decided payload rejected by payload predicate")
			}
			return out, nil
		}
		if ok {
			if !m.payloadValid(decided.Payload) {
				return ProposalValue{}, fmt.Errorf("mvba decided payload rejected by payload predicate")
			}
			return decided, nil
		}
		lastErr = fmt.Errorf("round %d finished without decision", round)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("mvba exhausted rounds without decision")
	}
	return ProposalValue{}, lastErr
}

func (m *DumboMVBA) payloadValid(payload []byte) bool {
	return m.cfg.ValidatePayload == nil || m.cfg.ValidatePayload(payload)
}

func (m *DumboMVBA) runCoinABA(
	ctx context.Context,
	round int,
	localHasValue bool,
	localValue ProposalValue,
) (bool, ProposalValue, error) {
	localBit := 0
	localPayload := []byte(nil)
	if localHasValue {
		localBit = 1
		localPayload = append([]byte(nil), localValue.Payload...)
	}
	vote := mvbaABAVoteMsg{
		Round:   round,
		Node:    m.cfg.ID,
		Bit:     localBit,
		Payload: localPayload,
	}
	if err := m.net.Broadcast(ProtocolMessage{
		Tag:    TagMVBAABA,
		Round:  round,
		Leader: -1,
		Body:   vote,
	}); err != nil {
		return false, ProposalValue{}, err
	}

	threshold := m.cfg.N - m.cfg.F
	if threshold <= 0 {
		threshold = 1
	}
	voteByNode := map[int]mvbaABAVoteMsg{
		m.cfg.ID: vote,
	}

	coinDigest := hashBytes(
		[]byte("MVBA_NON_EQ_COIN"),
		[]byte(m.cfg.SID),
		[]byte(fmt.Sprintf("|round=%d", round)),
	)
	coinShare, err := m.signer.Sign("MVBA_NON_EQ_COIN", coinDigest)
	if err != nil {
		return false, ProposalValue{}, err
	}
	if err := m.net.Broadcast(ProtocolMessage{
		Tag:    TagMVBAABACoin,
		Round:  round,
		Leader: -1,
		Body: mvbaABACoinMsg{
			Round: round,
			Node:  m.cfg.ID,
			Share: append([]byte(nil), coinShare...),
		},
	}); err != nil {
		return false, ProposalValue{}, err
	}
	coinShares := map[int][]byte{
		m.cfg.ID: append([]byte(nil), coinShare...),
	}

	deadline := time.NewTimer(m.cfg.WaitSPBCTimeout)
	defer deadline.Stop()
	for {
		if len(voteByNode) >= threshold && len(coinShares) >= threshold {
			break
		}
		select {
		case <-ctx.Done():
			return false, ProposalValue{}, ctx.Err()
		case <-deadline.C:
			return false, ProposalValue{}, fmt.Errorf("coin/aba round %d timeout", round)
		case in, ok := <-m.recv:
			if !ok {
				return false, ProposalValue{}, fmt.Errorf("mvba receive channel closed")
			}
			switch in.Msg.Tag {
			case TagMVBAABA:
				if in.Msg.Round != round {
					continue
				}
				msg, ok := in.Msg.Body.(mvbaABAVoteMsg)
				if !ok {
					continue
				}
				if msg.Node != in.From || (msg.Bit != 0 && msg.Bit != 1) {
					continue
				}
				if _, seen := voteByNode[msg.Node]; seen {
					continue
				}
				voteByNode[msg.Node] = msg
			case TagMVBAABACoin:
				if in.Msg.Round != round {
					continue
				}
				msg, ok := in.Msg.Body.(mvbaABACoinMsg)
				if !ok || msg.Node != in.From {
					continue
				}
				if _, seen := coinShares[msg.Node]; seen {
					continue
				}
				if !m.signer.Verify(msg.Node, "MVBA_NON_EQ_COIN", coinDigest, msg.Share) {
					continue
				}
				coinShares[msg.Node] = append([]byte(nil), msg.Share...)
			}
		}
	}

	keys := make([]int, 0, len(coinShares))
	for id := range coinShares {
		keys = append(keys, id)
	}
	sort.Ints(keys)
	coinMaterial := make([]byte, 0, len(keys)*64)
	for _, id := range keys {
		coinMaterial = append(coinMaterial, coinShares[id]...)
	}
	coinBit := int(hashBytes([]byte("MVBA_NON_EQ_BIT"), coinMaterial)[0] & 1)

	ones := 0
	zeros := 0
	candidates := make([]mvbaABAVoteMsg, 0, len(voteByNode))
	for _, v := range voteByNode {
		if v.Bit == 1 {
			ones++
			candidates = append(candidates, v)
		} else {
			zeros++
		}
	}
	if ones >= threshold && coinBit == 1 {
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].Node < candidates[j].Node
		})
		out := ProposalValue{
			Payload: append([]byte(nil), candidates[0].Payload...),
			Round:   round,
			Hint:    "non-equivalent-coin-aba",
		}
		return true, out, nil
	}
	if zeros >= threshold && coinBit == 0 {
		return false, ProposalValue{}, nil
	}
	if localHasValue && coinBit == 1 {
		return true, localValue, nil
	}
	return false, ProposalValue{}, nil
}

func (m *DumboMVBA) runRound(
	ctx context.Context,
	round int,
	leader int,
	handle *SPBCHandle,
) (ProposalValue, bool, error) {
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return ProposalValue{}, false, fmt.Errorf("round %d leader %d timeout", round, leader)
			}
			return ProposalValue{}, false, ctx.Err()
		case out, ok := <-handle.FinalOut:
			if !ok {
				return ProposalValue{}, false, fmt.Errorf("round %d leader %d final channel closed", round, leader)
			}
			if out.OK && out.Leader == leader {
				return cloneProposal(out.Value), true, nil
			}
		case in, ok := <-m.recv:
			if !ok {
				return ProposalValue{}, false, fmt.Errorf("mvba receive channel closed")
			}
			m.routeSPBCMessage(ctx, handle, round, leader, in)
		}
	}
}

func (m *DumboMVBA) routeSPBCMessage(
	ctx context.Context,
	handle *SPBCHandle,
	round int,
	leader int,
	in ReceivedMessage,
) {
	if in.Msg.Tag != TagSPBC || in.Msg.Round != round || in.Msg.Leader != leader {
		return
	}
	select {
	case <-ctx.Done():
		return
	case handle.Inbound <- RoutedSPBCMessage{From: in.From, Body: in.Msg.Body}:
	case <-time.After(m.cfg.RouteSendTimeout):
		if m.logger != nil {
			m.logger.Printf("drop SPBC route message round=%d leader=%d from=%d", round, leader, in.From)
		}
	}
}

func roundLeaderInput(id int, leader int, in ProposalValue) *ProposalValue {
	if id != leader {
		return nil
	}
	v := cloneProposal(in)
	return &v
}

func leaderOrder(sid string, n int, round int) []int {
	seedBytes := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", sid, round)))
	seed := int64(binary.BigEndian.Uint64(seedBytes[:8]))
	r := rand.New(rand.NewSource(seed))
	return r.Perm(n)
}

func cloneProposal(in ProposalValue) ProposalValue {
	out := ProposalValue{
		Round: in.Round,
		Hint:  in.Hint,
	}
	if len(in.Payload) > 0 {
		out.Payload = append([]byte(nil), in.Payload...)
	}
	if len(in.Proof) > 0 {
		out.Proof = make([]SigShare, len(in.Proof))
		for i := range in.Proof {
			out.Proof[i].Signer = in.Proof[i].Signer
			if len(in.Proof[i].Sig) > 0 {
				out.Proof[i].Sig = append([]byte(nil), in.Proof[i].Sig...)
			}
		}
	}
	return out
}
