package core

import (
	"context"
	"fmt"
)

func (m *DumboMVBA) runABA(
	ctx context.Context,
	sid string,
	iter int,
	input int,
	recv <-chan ReceivedMessage,
	coin func(nonce string) (int, error),
) (int, error) {
	n := m.cfg.N
	f := m.cfg.F
	threshold := 2*f + 1

	sendABA := func(body interface{}) {
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    TagMVBAABA,
				Round:  iter,
				Leader: 0,
				Body:   body,
			})
		}
	}
	sendDecision := func(v int) {
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    TagMVBAABADecision,
				Round:  iter,
				Leader: 0,
				Body: abaDecisionMsg{
					SID:   sid,
					Iter:  iter,
					Value: v,
				},
			})
		}
	}

	sendABA(abaEstMsg{SID: sid, Iter: iter, Value: input})
	seenEst := make(map[int]int, n)
	seenDec := make(map[int]int, n)
	seenEst[m.cfg.ID] = input
	selfDec := -1

	for {
		if selfDec >= 0 && countDecision(seenDec, selfDec) >= f+1 {
			return selfDec, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case abaEstMsg:
				if msg.SID != sid || msg.Iter != iter {
					continue
				}
				if msg.Value != 0 && msg.Value != 1 {
					continue
				}
				if _, exists := seenEst[in.From]; exists {
					continue
				}
				seenEst[in.From] = msg.Value
				if selfDec < 0 && len(seenEst) >= threshold {
					decision := deriveABADecision(seenEst, input)
					if decision < 0 {
						c, err := coin(fmt.Sprintf("aba-%d-%d", iter, len(seenEst)))
						if err != nil {
							return 0, err
						}
						decision = c % 2
					}
					selfDec = decision
					seenDec[m.cfg.ID] = decision
					sendDecision(decision)
				}
			case abaDecisionMsg:
				if msg.SID != sid || msg.Iter != iter {
					continue
				}
				if msg.Value != 0 && msg.Value != 1 {
					continue
				}
				if _, exists := seenDec[in.From]; exists {
					continue
				}
				seenDec[in.From] = msg.Value
				if selfDec < 0 {
					selfDec = msg.Value
					seenDec[m.cfg.ID] = selfDec
					sendDecision(selfDec)
				}
				if countDecision(seenDec, msg.Value) >= f+1 {
					return msg.Value, nil
				}
			}
		}
	}
}

func deriveABADecision(est map[int]int, fallback int) int {
	if fallback == 0 || fallback == 1 {
		if allSame(est, fallback) {
			return fallback
		}
	}
	if allSame(est, 0) {
		return 0
	}
	if allSame(est, 1) {
		return 1
	}
	return -1
}

func allSame(est map[int]int, v int) bool {
	if len(est) == 0 {
		return false
	}
	for _, x := range est {
		if x != v {
			return false
		}
	}
	return true
}

func countDecision(dec map[int]int, v int) int {
	n := 0
	for _, x := range dec {
		if x == v {
			n++
		}
	}
	return n
}
