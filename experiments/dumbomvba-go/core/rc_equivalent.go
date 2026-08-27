package core

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"
)

func rcResponsibilityFanout(n, f int) int {
	raw := os.Getenv("PRACTICAL_MVBA_RC_RESPONSIBILITY_FANOUT")
	if raw == "" {
		return n
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 || v > n {
		return n
	}
	minimum := n - f
	if v < minimum {
		return minimum
	}
	return v
}

func rcResponsibilityRecipients(sender, n, fanout int) []int {
	if n <= 0 || fanout <= 0 {
		return nil
	}
	if fanout > n {
		fanout = n
	}
	recipients := make([]int, fanout)
	for offset := range recipients {
		recipients[offset] = (sender + offset) % n
	}
	return recipients
}

func (m *DumboMVBA) runRCSubprotocol(
	ctx context.Context,
	sid string,
	recv <-chan ReceivedMessage,
	store *rcStoreMsg,
	lock *pdLockMsg,
) ([]byte, error) {
	n := m.cfg.N
	f := m.cfg.F
	threshold := n - f
	// Use the same erasure-code parameters as PD (Provable Dissemination).
	// PD encodes with k = n - 2f. The f+1 threshold previously used is only
	// equal to n-2f when n = 3f+1. For general n ≥ 3f+1, we must match PD.
	k := n - 2*f
	if k <= 0 {
		k = 1
	}

	// RC dissemination is a best-effort fan-out. A peer may have already
	// completed MVBA and closed its listener while this node is still
	// reconstructing a value. Keeping the old sequential Send loop here made
	// one failed peer's retry/backoff stall the only goroutine consuming RC
	// shards. Bound the fan-out wait by the protocol route timeout; certificate
	// and shard validation below remain unchanged.
	sendWait := m.cfg.RouteSendTimeout
	if sendWait <= 0 {
		sendWait = 300 * time.Millisecond
	}
	broadcastRC := func(body interface{}) {
		broadcastEquivalent(ctx, m.net, n, sendWait, ProtocolMessage{
			Tag: TagMVBARC, Round: 0, Leader: 0, Body: body,
		})
	}
	storeFanout := rcResponsibilityFanout(n, f)
	broadcastStore := func(body rcStoreMsg) {
		if storeFanout >= n {
			broadcastRC(body)
			return
		}
		recipients := rcResponsibilityRecipients(m.cfg.ID, n, storeFanout)
		broadcastEquivalentTo(ctx, m.net, recipients, sendWait, ProtocolMessage{
			Tag: TagMVBARC, Round: 0, Leader: 0, Body: body,
		})
	}

	if lock != nil {
		broadcastRC(*lock)
	}
	if store != nil {
		m.cacheRCStore(store)
		broadcastStore(*store)
	}

	commit := make(map[string][][]byte)
	seenStoreByRoot := make(map[string]map[int]struct{})
	servedPull := make(map[int]int, n)
	pullAttempts := 0
	rebroadcastLock := false
	var certifiedRoot []byte
	var pullTimer *time.Timer
	var pullC <-chan time.Time
	defer func() {
		if pullTimer != nil {
			pullTimer.Stop()
		}
	}()

	tryDecode := func(root []byte) ([]byte, bool) {
		shards := commit[fmt.Sprintf("%x", root)]
		if countNonNilShards(shards) < k {
			return nil, false
		}
		val, err := erasureDecodeValue(shards, k, n)
		if err != nil {
			return nil, false
		}
		reencoded, err := erasureEncodeValue(val, k, n)
		if err != nil {
			return nil, false
		}
		decodedRoot, _ := buildMerkle(reencoded)
		return val, sameRoot(decodedRoot, root)
	}
	schedulePull := func() {
		if storeFanout >= n || pullTimer != nil {
			return
		}
		delay := sendWait
		if raw := os.Getenv("PRACTICAL_MVBA_RC_PULL_DELAY_MS"); raw != "" {
			if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
				delay = time.Duration(ms) * time.Millisecond
			}
		}
		if delay < 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		pullTimer = time.NewTimer(delay)
		pullC = pullTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pullC:
			pullC = nil
			if len(certifiedRoot) > 0 {
				if val, ok := tryDecode(certifiedRoot); ok {
					return val, nil
				}
				broadcastRCRequest := ProtocolMessage{Tag: TagMVBARCPull, Round: 0, Leader: 0, Body: rcPullRequest{
					SID: sid, Root: append([]byte(nil), certifiedRoot...), Requester: m.cfg.ID,
				}}
				broadcastEquivalent(ctx, m.net, n, sendWait, broadcastRCRequest)
				pullAttempts++
				if pullAttempts < f+3 {
					delay := time.Duration(pullAttempts+1) * sendWait
					if delay < 200*time.Millisecond {
						delay = 200 * time.Millisecond
					}
					pullTimer.Reset(delay)
					pullC = pullTimer.C
				}
			}
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case pdLockMsg:
				if msg.SID != sid {
					continue
				}
				dig := pdCertificateDigest("PD_STORED", sid, msg.Leader, msg.Root)
				if msg.Leader < 0 || msg.Leader >= n || !verifyThresholdCertificate(
					m.signer, "PD_STORED", dig, msg.Certificate, threshold,
				) {
					continue
				}
				if !rebroadcastLock {
					broadcastRC(msg)
					rebroadcastLock = true
				}
				certifiedRoot = append(certifiedRoot[:0], msg.Root...)
				if val, ok := tryDecode(certifiedRoot); ok {
					return val, nil
				}
				schedulePull()
			case rcStoreMsg:
				if msg.SID != sid || msg.From != in.From || msg.From < 0 || msg.From >= n ||
					msg.Branch.Index != msg.From {
					continue
				}
				rootKey := fmt.Sprintf("%x", msg.Root)
				seenBySender := seenStoreByRoot[rootKey]
				if seenBySender == nil {
					seenBySender = make(map[int]struct{}, n)
					seenStoreByRoot[rootKey] = seenBySender
				}
				if _, seen := seenBySender[msg.From]; seen {
					continue
				}
				if !verifyMerkle(msg.Stripe, msg.Root, msg.Branch) {
					continue
				}
				seenBySender[msg.From] = struct{}{}
				shards, ok := commit[rootKey]
				if !ok {
					shards = make([][]byte, n)
				}
				shards[msg.From] = append([]byte(nil), msg.Stripe...)
				commit[rootKey] = shards
				if sameRoot(certifiedRoot, msg.Root) {
					if val, ok := tryDecode(certifiedRoot); ok {
						return val, nil
					}
				}
			case rcPullRequest:
				responseStore := store
				if responseStore == nil {
					responseStore, _ = m.cachedRCStore(msg.SID)
				}
				if msg.SID != sid || msg.Requester != in.From || msg.Requester < 0 || msg.Requester >= n ||
					responseStore == nil || responseStore.SID != sid || !sameRoot(responseStore.Root, msg.Root) {
					continue
				}
				if servedPull[msg.Requester] >= f+3 {
					continue
				}
				servedPull[msg.Requester]++
				_ = m.net.Send(msg.Requester, ProtocolMessage{
					Tag: TagMVBARC, Round: 0, Leader: 0, Body: *responseStore,
				})
			default:
				continue
			}
		}
	}
}

// broadcastEquivalent fans out one protocol message without allowing a
// stalled peer to stop the caller from processing already delivered messages.
// Send has no context parameter, so timed-out sends finish in their own
// goroutine and are reclaimed when the session transport closes.
func broadcastEquivalent(
	ctx context.Context,
	net Network,
	n int,
	wait time.Duration,
	msg ProtocolMessage,
) {
	if ctx == nil || net == nil || n <= 0 {
		return
	}
	if wait <= 0 {
		wait = 300 * time.Millisecond
	}
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			_ = net.Send(i, msg)
			done <- struct{}{}
		}()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for completed := 0; completed < n; completed++ {
		select {
		case <-ctx.Done():
			return
		case <-done:
		case <-timer.C:
			return
		}
	}
}

func broadcastEquivalentTo(ctx context.Context, net Network, recipients []int, wait time.Duration, msg ProtocolMessage) {
	if ctx == nil || net == nil || len(recipients) == 0 {
		return
	}
	if wait <= 0 {
		wait = 300 * time.Millisecond
	}
	done := make(chan struct{}, len(recipients))
	for _, recipient := range recipients {
		recipient := recipient
		go func() {
			_ = net.Send(recipient, msg)
			done <- struct{}{}
		}()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for completed := 0; completed < len(recipients); completed++ {
		select {
		case <-ctx.Done():
			return
		case <-done:
		case <-timer.C:
			return
		}
	}
}

func countNonNilShards(shards [][]byte) int {
	n := 0
	for i := range shards {
		if shards[i] != nil {
			n++
		}
	}
	return n
}
