package core

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
)

func (m *DumboMVBA) runEquivalent(ctx context.Context, input ProposalValue) (ProposalValue, error) {
	n := m.cfg.N
	sid := m.cfg.SID

	pdRecvs := make([]chan ReceivedMessage, n)
	for i := 0; i < n; i++ {
		pdRecvs[i] = make(chan ReceivedMessage, 2048)
	}
	coinRecv := make(chan ReceivedMessage, 2048)
	pdFinishRecv := make(chan ReceivedMessage, 4096)
	rcRecv := make(chan ReceivedMessage, 4096)
	rcPrepareRecv := make(chan ReceivedMessage, 4096)

	maxABABuffers := m.cfg.MaxRounds*4 + 8
	if maxABABuffers < n+2 {
		maxABABuffers = n + 2
	}
	abaRecvs := make([]chan ReceivedMessage, maxABABuffers)
	abaCoinRecvs := make([]chan ReceivedMessage, maxABABuffers)
	for i := 0; i < maxABABuffers; i++ {
		abaRecvs[i] = make(chan ReceivedMessage, 2048)
		abaCoinRecvs[i] = make(chan ReceivedMessage, 2048)
	}

	routerCtx, cancelRouter := context.WithCancel(ctx)
	defer cancelRouter()
	go m.routeEquivalentMessages(routerCtx, pdRecvs, coinRecv, pdFinishRecv, rcRecv, rcPrepareRecv, abaRecvs, abaCoinRecvs)

	store := make([]*rcStoreMsg, n)
	lock := make([]*pdLockMsg, n)

	type pdRes struct {
		leader int
		out    *pdOutcome
		err    error
	}
	pdCtx, cancelPD := context.WithCancel(routerCtx)
	defer cancelPD()
	pdOutCh := make(chan pdRes, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for leader := 0; leader < n; leader++ {
		leader := leader
		go func() {
			defer wg.Done()
			pdInput := []byte(nil)
			if leader == m.cfg.ID {
				pdInput = append([]byte(nil), input.Payload...)
			}
			out, err := m.runPDInstance(pdCtx, sid+"PD"+itoa(leader), leader, pdInput, pdRecvs[leader])
			pdOutCh <- pdRes{leader: leader, out: out, err: err}
		}()
	}
	pdCollected := make(chan struct{})
	go func() {
		defer close(pdCollected)
		for res := range pdOutCh {
			if res.err != nil || res.out == nil {
				continue
			}
			store[res.leader] = res.out.store
			lock[res.leader] = res.out.lock
		}
	}()
	pdWorkersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(pdOutCh)
		close(pdWorkersDone)
	}()

	// QuitPD validates n-f distinct PD DONE proofs. Waiting for all n local PD
	// instances here makes one silent/slow leader block an otherwise live MVBA.
	// DONE messages are mirrored to pdFinishRecv by the router as soon as they
	// arrive, while local PD workers continue retaining shards and locks for RC.
	if _, err := m.runQuitPD(routerCtx, sid, pdFinishRecv); err != nil {
		cancelPD()
		<-pdWorkersDone
		<-pdCollected
		return ProposalValue{}, fmt.Errorf("quitpd failed: %w", err)
	}
	cancelPD()
	<-pdWorkersDone
	<-pdCollected

	permutationCoin := m.makeSharedCoin(routerCtx, sid+"COIN", TagMVBACoin, 0, coinRecv)
	seed, err := permutationCoin("permutation")
	if err != nil {
		return ProposalValue{}, fmt.Errorf("permutation coin failed: %w", err)
	}
	permRnd := rand.New(rand.NewSource(int64(seed)))
	pi := permRnd.Perm(n)

	for r := 0; r < len(pi); r++ {
		l := pi[r]
		preMsg := rcPrepareMsg{
			SID:    sid + "RCprepare",
			Leader: l,
			Lock:   cloneLock(lock[l]),
		}
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    TagMVBARCPrepare,
				Round:  r,
				Leader: l,
				Body:   preMsg,
			})
		}

		rcBallot, err := m.runRCPrepare(routerCtx, sid, l, rcPrepareRecv)
		if err != nil {
			return ProposalValue{}, fmt.Errorf("rc-prepare leader=%d failed: %w", l, err)
		}

		abaCoin := m.makeSharedCoin(routerCtx, sid+"COIN"+itoa(r), TagMVBAABACoin, r, abaCoinRecvs[r])
		abaOut, err := m.runABA(routerCtx, sid+"ABA"+itoa(r), r, rcBallot, abaRecvs[r], abaCoin)
		if err != nil {
			return ProposalValue{}, fmt.Errorf("aba[%d] failed: %w", r, err)
		}
		if abaOut == 1 {
			dec, err := m.runRCSubprotocol(routerCtx, sid+"PD"+itoa(l), rcRecv, store[l], lock[l])
			if err != nil {
				return ProposalValue{}, fmt.Errorf("rc-subprotocol leader=%d failed: %w", l, err)
			}
			// RC already binds the decoded bytes to the certified Merkle root.
			// Application validity is deterministic, so all honest nodes skip the
			// same invalid recovered leader and advance in the common permutation.
			if !m.payloadValid(dec) {
				continue
			}
			return ProposalValue{
				Payload: dec,
				Round:   r,
				Hint:    "equivalent",
			}, nil
		}
	}

	return ProposalValue{}, fmt.Errorf("mvba equivalent exhausted permutation without decision")
}

func (m *DumboMVBA) routeEquivalentMessages(
	ctx context.Context,
	pdRecvs []chan ReceivedMessage,
	coinRecv chan ReceivedMessage,
	pdFinishRecv chan ReceivedMessage,
	rcRecv chan ReceivedMessage,
	rcPrepareRecv chan ReceivedMessage,
	abaRecvs []chan ReceivedMessage,
	abaCoinRecvs []chan ReceivedMessage,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case in, ok := <-m.recv:
			if !ok {
				return
			}
			switch in.Msg.Tag {
			case TagMVBAPD:
				if in.Msg.Leader >= 0 && in.Msg.Leader < len(pdRecvs) {
					trySend(ctx, pdRecvs[in.Msg.Leader], in)
				}
				if _, ok := in.Msg.Body.(pdDoneMsg); ok {
					trySend(ctx, pdFinishRecv, in)
				}
			case TagMVBACoin:
				trySend(ctx, coinRecv, in)
			case TagMVBAPDFinish:
				trySend(ctx, pdFinishRecv, in)
			case TagMVBARC, TagMVBARCPull:
				trySend(ctx, rcRecv, in)
			case TagMVBARCPrepare:
				trySend(ctx, rcPrepareRecv, in)
			case TagMVBAABA, TagMVBAABADecision:
				if in.Msg.Round >= 0 && in.Msg.Round < len(abaRecvs) {
					trySend(ctx, abaRecvs[in.Msg.Round], in)
				}
			case TagMVBAABACoin:
				if in.Msg.Round >= 0 && in.Msg.Round < len(abaCoinRecvs) {
					trySend(ctx, abaCoinRecvs[in.Msg.Round], in)
				}
			case TagSPBC:
				// Ignore SPBC messages in equivalent path.
			}
		}
	}
}

func (m *DumboMVBA) runQuitPD(ctx context.Context, sid string, recv <-chan ReceivedMessage) (int, error) {
	n := m.cfg.N
	f := m.cfg.F
	readyThreshold := f + 1
	provenThreshold := n - f

	provens := 0
	seenDone := make(map[int]struct{}, n)
	seenReady := make(map[int]struct{}, n)
	seenFinish := make(map[int]struct{}, n)
	readyShares := make(map[int][]byte, n)
	finishSent := false

	sendFinish := func(certificate []byte) {
		msg := quitFinishMsg{SID: sid, Certificate: append([]byte(nil), certificate...)}
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    TagMVBAPDFinish,
				Round:  0,
				Leader: m.cfg.ID,
				Body:   msg,
			})
		}
	}
	sendReady := func() error {
		dig := hashBytes([]byte("PD_QUIT_READY"), []byte(sid))
		share, err := m.signer.Sign("PD_QUIT_READY", dig)
		if err != nil {
			return err
		}
		msg := quitReadyMsg{
			SID:   sid,
			Share: share,
		}
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    TagMVBAPDFinish,
				Round:  0,
				Leader: m.cfg.ID,
				Body:   msg,
			})
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case pdDoneMsg:
				if msg.Leader < 0 || msg.Leader >= n || msg.SID != sid+"PD"+itoa(msg.Leader) {
					continue
				}
				if _, seen := seenDone[msg.Leader]; seen {
					continue
				}
				dig := pdCertificateDigest("PD_LOCKED", msg.SID, msg.Leader, msg.Root)
				if !verifyThresholdCertificate(m.signer, "PD_LOCKED", dig, msg.Certificate, provenThreshold) {
					continue
				}
				seenDone[msg.Leader] = struct{}{}
				provens++
				if provens == provenThreshold {
					if err := sendReady(); err != nil {
						return -1, err
					}
				}
			case quitReadyMsg:
				if msg.SID != sid {
					continue
				}
				if _, seen := seenReady[in.From]; seen {
					continue
				}
				dig := hashBytes([]byte("PD_QUIT_READY"), []byte(sid))
				if !m.signer.Verify(in.From, "PD_QUIT_READY", dig, msg.Share) {
					continue
				}
				seenReady[in.From] = struct{}{}
				readyShares[in.From] = append([]byte(nil), msg.Share...)
				if len(readyShares) >= readyThreshold && !finishSent {
					certificate, err := recoverThresholdCertificate(
						m.signer, "PD_QUIT_READY", dig, readyShares, readyThreshold,
					)
					if err != nil {
						return -1, err
					}
					sendFinish(certificate)
					finishSent = true
				}
			case quitFinishMsg:
				if msg.SID != sid {
					continue
				}
				if _, seen := seenFinish[in.From]; seen {
					continue
				}
				seenFinish[in.From] = struct{}{}
				dig := hashBytes([]byte("PD_QUIT_READY"), []byte(sid))
				if !verifyThresholdCertificate(m.signer, "PD_QUIT_READY", dig, msg.Certificate, readyThreshold) {
					continue
				}
				if !finishSent {
					sendFinish(msg.Certificate)
					finishSent = true
				}
				return in.From, nil
			}
		}
	}
}

func (m *DumboMVBA) runRCPrepare(ctx context.Context, sid string, leader int, recv <-chan ReceivedMessage) (int, error) {
	f := m.cfg.F
	threshold := 2*f + 1
	rcSeen := make(map[int]struct{}, m.cfg.N)
	hasValidLock := false
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case in := <-recv:
			msg, ok := in.Msg.Body.(rcPrepareMsg)
			if !ok || msg.Leader != leader || msg.SID != sid+"RCprepare" {
				continue
			}
			if _, seen := rcSeen[in.From]; seen {
				continue
			}
			rcSeen[in.From] = struct{}{}
			if msg.Lock != nil {
				dig := pdCertificateDigest("PD_STORED", sid+"PD"+itoa(leader), leader, msg.Lock.Root)
				if msg.Lock.Leader == leader && verifyThresholdCertificate(
					m.signer, "PD_STORED", dig, msg.Lock.Certificate, m.cfg.N-m.cfg.F,
				) {
					hasValidLock = true
				}
			}
			if len(rcSeen) >= threshold {
				if hasValidLock {
					return 1, nil
				}
				return 0, nil
			}
		}
	}
}

func trySend(ctx context.Context, ch chan ReceivedMessage, in ReceivedMessage) {
	select {
	case <-ctx.Done():
		return
	case ch <- in:
	default:
		select {
		case <-ctx.Done():
			return
		case ch <- in:
		}
	}
}

func cloneLock(in *pdLockMsg) *pdLockMsg {
	if in == nil {
		return nil
	}
	return &pdLockMsg{
		SID: in.SID, Leader: in.Leader, Root: append([]byte(nil), in.Root...),
		Certificate: append([]byte(nil), in.Certificate...),
	}
}

func itoa(v int) string {
	return fmt.Sprintf("%d", v)
}
