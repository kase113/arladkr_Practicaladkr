package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"
)

func pdResponsibilityFanout(n, f int) int {
	raw := os.Getenv("PRACTICAL_MVBA_PD_RESPONSIBILITY_FANOUT")
	if raw == "" {
		return n - f
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 || v > n {
		return n
	}
	if v < n-f {
		return n - f
	}
	return v
}

func pdResponsibilityRecipients(leader, n, fanout int) []int {
	if n <= 0 || fanout <= 0 {
		return nil
	}
	if fanout > n {
		fanout = n
	}
	out := make([]int, fanout)
	for offset := range out {
		out[offset] = (leader + offset) % n
	}
	return out
}

type pdOutcome struct {
	store *rcStoreMsg
	lock  *pdLockMsg
	done  *pdDoneMsg
}

func (m *DumboMVBA) runPDInstance(
	ctx context.Context,
	sid string,
	leader int,
	input []byte,
	recv <-chan ReceivedMessage,
) (*pdOutcome, error) {
	n := m.cfg.N
	f := m.cfg.F
	threshold := n - f
	k := n - 2*f

	sendPD := func(to int, body interface{}) {
		_ = m.net.Send(to, ProtocolMessage{
			Tag:    TagMVBAPD,
			Round:  0,
			Leader: leader,
			Body:   body,
		})
	}
	broadcastPD := func(body interface{}) {
		for i := 0; i < n; i++ {
			sendPD(i, body)
		}
	}

	out := &pdOutcome{}
	storedShares := make(map[int][]byte, n)
	lockedShares := make(map[int][]byte, n)
	seenStored := make(map[int]struct{}, n)
	seenLocked := make(map[int]struct{}, n)
	seenStoreFromLeader := false
	seenLockFromLeader := false
	lockSent := false
	pullAttempts := 0
	replacementNext := pdResponsibilityFanout(n, f)
	var pullTimer *time.Timer
	var pullC <-chan time.Time
	defer func() {
		if pullTimer != nil {
			pullTimer.Stop()
		}
	}()
	var stripes [][]byte
	var root []byte
	var branches []merkleBranch

	if m.cfg.ID == leader {
		var err error
		stripes, err = erasureEncodeValue(input, k, n)
		if err != nil {
			return nil, err
		}
		root, branches = buildMerkle(stripes)
		for _, i := range pdResponsibilityRecipients(leader, n, pdResponsibilityFanout(n, f)) {
			sendPD(i, pdStoreMsg{
				SID:    sid,
				Root:   root,
				Stripe: append([]byte(nil), stripes[i]...),
				Branch: merkleBranch{
					Index:    branches[i].Index,
					Siblings: cloneSiblings(branches[i].Siblings),
				},
			})
		}
	}
	if m.cfg.ID == leader && pdResponsibilityFanout(n, f) < n {
		delay := m.cfg.RouteSendTimeout
		if delay <= 0 {
			delay = 300 * time.Millisecond
		}
		pullTimer = time.NewTimer(delay)
		pullC = pullTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pullC:
			if m.cfg.ID == leader && !lockSent && len(storedShares) < threshold {
				candidates := pdResponsibilityRecipients(leader, n, n)
				if replacementNext < len(candidates) {
					candidate := candidates[replacementNext]
					replacementNext++
					pullAttempts++
					sendPD(candidate, pdStoreMsg{SID: sid, Root: append([]byte(nil), root...), Stripe: append([]byte(nil), stripes[candidate]...), Branch: merkleBranch{Index: branches[candidate].Index, Siblings: cloneSiblings(branches[candidate].Siblings)}})
					pullTimer.Reset(time.Duration(1+pullAttempts/3) * time.Second)
					pullC = pullTimer.C
					continue
				}
			}
			pullC = nil
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case pdStoreMsg:
				if msg.SID != sid || in.From != leader || seenStoreFromLeader || msg.Branch.Index != m.cfg.ID {
					continue
				}
				if !verifyMerkle(msg.Stripe, msg.Root, msg.Branch) {
					continue
				}
				seenStoreFromLeader = true
				out.store = &rcStoreMsg{
					SID:    sid,
					Root:   append([]byte(nil), msg.Root...),
					From:   m.cfg.ID,
					Stripe: append([]byte(nil), msg.Stripe...),
					Branch: merkleBranch{
						Index:    msg.Branch.Index,
						Siblings: cloneSiblings(msg.Branch.Siblings),
					},
				}
				m.cacheRCStore(out.store)
				dig := pdCertificateDigest("PD_STORED", sid, leader, msg.Root)
				share, err := m.signer.Sign("PD_STORED", dig)
				if err != nil {
					return nil, err
				}
				sendPD(leader, pdStoredMsg{
					SID:   sid,
					Root:  append([]byte(nil), msg.Root...),
					Share: append([]byte(nil), share...),
				})
				if m.cfg.ID != leader && out.lock != nil {
					return out, nil
				}
			case pdPullRequest:
				if m.cfg.ID != leader || msg.SID != sid || msg.Requester != in.From ||
					msg.Requester < 0 || msg.Requester >= n || msg.Index < 0 || msg.Index >= n ||
					len(root) == 0 || len(stripes) != n || (len(msg.Root) > 0 && !sameRoot(msg.Root, root)) {
					continue
				}
				sendPD(msg.Requester, pdStoreMsg{
					SID: sid, Root: append([]byte(nil), root...),
					Stripe: append([]byte(nil), stripes[msg.Index]...),
					Branch: merkleBranch{Index: branches[msg.Index].Index, Siblings: cloneSiblings(branches[msg.Index].Siblings)},
				})
			case pdStoredMsg:
				if msg.SID != sid || m.cfg.ID != leader {
					continue
				}
				if _, seen := seenStored[in.From]; seen {
					continue
				}
				dig := pdCertificateDigest("PD_STORED", sid, leader, msg.Root)
				if !m.signer.Verify(in.From, "PD_STORED", dig, msg.Share) {
					continue
				}
				seenStored[in.From] = struct{}{}
				storedShares[in.From] = append([]byte(nil), msg.Share...)
				if len(storedShares) >= threshold && !lockSent {
					certificate, err := recoverThresholdCertificate(m.signer, "PD_STORED", dig, storedShares, threshold)
					if err != nil {
						return nil, err
					}
					lockSent = true
					broadcastPD(pdLockMsg{
						SID: sid, Leader: leader, Root: append([]byte(nil), msg.Root...),
						Certificate: append([]byte(nil), certificate...),
					})
				}
			case pdLockMsg:
				if msg.SID != sid || msg.Leader != leader || in.From != leader || seenLockFromLeader {
					continue
				}
				dig := pdCertificateDigest("PD_STORED", sid, leader, msg.Root)
				if !verifyThresholdCertificate(m.signer, "PD_STORED", dig, msg.Certificate, threshold) {
					continue
				}
				seenLockFromLeader = true
				out.lock = &pdLockMsg{
					SID: sid, Leader: leader, Root: append([]byte(nil), msg.Root...),
					Certificate: append([]byte(nil), msg.Certificate...),
				}
				dig2 := pdCertificateDigest("PD_LOCKED", sid, leader, msg.Root)
				share, err := m.signer.Sign("PD_LOCKED", dig2)
				if err != nil {
					return nil, err
				}
				sendPD(leader, pdLockedMsg{
					SID:   sid,
					Root:  append([]byte(nil), msg.Root...),
					Share: append([]byte(nil), share...),
				})
				if m.cfg.ID != leader && out.store != nil {
					return out, nil
				}
			case pdLockedMsg:
				if msg.SID != sid || m.cfg.ID != leader {
					continue
				}
				if _, seen := seenLocked[in.From]; seen {
					continue
				}
				dig := pdCertificateDigest("PD_LOCKED", sid, leader, msg.Root)
				if !m.signer.Verify(in.From, "PD_LOCKED", dig, msg.Share) {
					continue
				}
				seenLocked[in.From] = struct{}{}
				lockedShares[in.From] = append([]byte(nil), msg.Share...)
				if len(lockedShares) >= threshold {
					certificate, err := recoverThresholdCertificate(m.signer, "PD_LOCKED", dig, lockedShares, threshold)
					if err != nil {
						return nil, err
					}
					done := &pdDoneMsg{
						SID: sid, Leader: leader, Root: append([]byte(nil), msg.Root...),
						Certificate: append([]byte(nil), certificate...),
					}
					out.done = done
					broadcastPD(*done)
					return out, nil
				}
			case pdDoneMsg:
				if msg.SID != sid {
					continue
				}
				// keep listening; done is consumed by quitPD phase.
			default:
				continue
			}
		}
	}
}

func cloneShares(in []SigShare) []SigShare {
	out := make([]SigShare, len(in))
	for i := range in {
		out[i].Signer = in[i].Signer
		if len(in[i].Sig) > 0 {
			out[i].Sig = append([]byte(nil), in[i].Sig...)
		}
	}
	return out
}

func cloneSiblings(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func sameRoot(a []byte, b []byte) bool {
	return bytes.Equal(a, b)
}

func proofKey(root []byte) string {
	return fmt.Sprintf("%x", root)
}
