package core

import (
	"context"
	"fmt"
)

const (
	abaPhaseEST  = "EST"
	abaPhaseAUX  = "AUX"
	abaPhaseCONF = "CONF"
)

// runABA implements the MMR14 binary agreement round used by DumboMVBA.
func (m *DumboMVBA) runABA(
	ctx context.Context,
	sid string,
	iter int,
	input int,
	recv <-chan ReceivedMessage,
	coin func(nonce string) (int, error),
) (int, error) {
	n, f := m.cfg.N, m.cfg.F
	if n < 3*f+1 || input < 0 || input > 1 {
		return 0, fmt.Errorf("invalid ABA parameters n=%d f=%d input=%d", n, f, input)
	}
	quorum := n - f

	broadcast := func(msg abaPhaseMsg) {
		for peer := 0; peer < n; peer++ {
			_ = m.net.Send(peer, ProtocolMessage{
				Tag:    TagMVBAABA,
				Round:  iter,
				Leader: 0,
				Body:   msg,
			})
		}
	}

	// Messages from a faster peer can arrive before this node advances to the
	// corresponding internal round. Keep them instead of dropping them.
	pending := make(map[int][]ReceivedMessage)
	nextMessage := func(round int) (ReceivedMessage, bool, error) {
		if len(pending[round]) > 0 {
			msg := pending[round][0]
			pending[round] = pending[round][1:]
			return msg, true, nil
		}
		select {
		case <-ctx.Done():
			return ReceivedMessage{}, false, ctx.Err()
		case msg, ok := <-recv:
			if !ok {
				return ReceivedMessage{}, false, fmt.Errorf("ABA receive channel closed")
			}
			body, ok := msg.Msg.Body.(abaPhaseMsg)
			if !ok || body.SID != sid || body.Iter != iter {
				return msg, false, nil
			}
			if body.Round != round {
				if body.Round > round {
					pending[body.Round] = append(pending[body.Round], msg)
				}
				return msg, false, nil
			}
			return msg, true, nil
		}
	}

	estimate := input
	decision := -1
	for abaRound := 0; ; abaRound++ {
		est := [2]map[int]struct{}{make(map[int]struct{}, n), make(map[int]struct{}, n)}
		estSent := [2]bool{}
		bin := make(map[int]struct{}, 2)
		aux := [2]map[int]struct{}{make(map[int]struct{}, n), make(map[int]struct{}, n)}
		conf := make(map[string]map[int]struct{}, 3)
		confValues := make(map[string][]int, 3)

		sendEST := func(v int) {
			if v != 0 && v != 1 || estSent[v] {
				return
			}
			estSent[v] = true
			est[v][m.cfg.ID] = struct{}{}
			broadcast(abaPhaseMsg{SID: sid, Iter: iter, Round: abaRound, Phase: abaPhaseEST, Value: v})
		}
		sendEST(estimate)
		accept := func(msg ReceivedMessage) {
			body, ok := msg.Msg.Body.(abaPhaseMsg)
			if !ok || body.SID != sid || body.Iter != iter || body.Round != abaRound || msg.From < 0 || msg.From >= n {
				return
			}
			switch body.Phase {
			case abaPhaseEST:
				if body.Value < 0 || body.Value > 1 {
					return
				}
				if _, seen := est[body.Value][msg.From]; seen {
					return
				}
				est[body.Value][msg.From] = struct{}{}
				if len(est[body.Value]) >= f+1 {
					sendEST(body.Value)
				}
				if len(est[body.Value]) >= 2*f+1 {
					bin[body.Value] = struct{}{}
				}
			case abaPhaseAUX:
				if body.Value >= 0 && body.Value <= 1 {
					aux[body.Value][msg.From] = struct{}{}
				}
			case abaPhaseCONF:
				values := normalizeABAValues(body.Values)
				if len(values) == 0 {
					return
				}
				key := abaValuesKey(values)
				if conf[key] == nil {
					conf[key] = make(map[int]struct{}, n)
					confValues[key] = values
				}
				conf[key][msg.From] = struct{}{}
			}
		}

		for len(bin) == 0 {
			msg, ok, err := nextMessage(abaRound)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			accept(msg)
		}

		auxValue := 0
		if _, ok := bin[0]; !ok {
			auxValue = 1
		}
		aux[auxValue][m.cfg.ID] = struct{}{}
		broadcast(abaPhaseMsg{SID: sid, Iter: iter, Round: abaRound, Phase: abaPhaseAUX, Value: auxValue})

		values := []int(nil)
		for len(values) == 0 {
			if _, ok := bin[1]; ok && len(aux[1]) >= quorum {
				values = []int{1}
			} else if _, ok := bin[0]; ok && len(aux[0]) >= quorum {
				values = []int{0}
			} else {
				seen := make(map[int]struct{}, quorum)
				for v := range bin {
					for sender := range aux[v] {
						seen[sender] = struct{}{}
					}
				}
				if len(seen) >= quorum {
					if _, ok := bin[0]; ok {
						values = append(values, 0)
					}
					if _, ok := bin[1]; ok {
						values = append(values, 1)
					}
				}
			}
			if len(values) > 0 {
				break
			}
			msg, ok, err := nextMessage(abaRound)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			accept(msg)
		}

		confKey := abaValuesKey(values)
		conf[confKey] = map[int]struct{}{m.cfg.ID: {}}
		confValues[confKey] = append([]int(nil), values...)
		broadcast(abaPhaseMsg{
			SID: sid, Iter: iter, Round: abaRound, Phase: abaPhaseCONF,
			Values: append([]int(nil), confValues[confKey]...),
		})

		var decidedValues []int
		for len(decidedValues) == 0 {
			compatible := make(map[int]struct{}, quorum)
			for key, senders := range conf {
				if abaValuesSubset(confValues[key], bin) {
					for sender := range senders {
						compatible[sender] = struct{}{}
					}
				}
			}
			for _, v := range []int{1, 0} {
				key := abaSingleValueKey(v)
				if _, inBin := bin[v]; inBin && len(conf[key]) >= quorum {
					decidedValues = []int{v}
					break
				}
			}
			if len(decidedValues) == 0 && len(compatible) >= quorum {
				decidedValues = []int{0, 1}
			}
			if len(decidedValues) > 0 {
				break
			}
			msg, ok, err := nextMessage(abaRound)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			accept(msg)
		}

		coinValue, err := coin(fmt.Sprintf("round-%d", abaRound))
		if err != nil {
			return 0, err
		}
		coinValue &= 1
		if len(decidedValues) == 1 {
			v := decidedValues[0]
			if v == coinValue {
				// Require a second matching round before returning.
				if decision == v {
					return v, nil
				}
				decision = v
			}
			estimate = v
		} else {
			estimate = coinValue
		}
	}
}

func normalizeABAValues(values []int) []int {
	seen := [2]bool{}
	for _, v := range values {
		if v < 0 || v > 1 || seen[v] {
			return nil
		}
		seen[v] = true
	}
	result := make([]int, 0, 2)
	if seen[0] {
		result = append(result, 0)
	}
	if seen[1] {
		result = append(result, 1)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func binValues(values map[int]struct{}) []int {
	result := make([]int, 0, len(values))
	for _, v := range []int{0, 1} {
		if _, ok := values[v]; ok {
			result = append(result, v)
		}
	}
	return result
}

func abaValuesKey(values interface{}) string {
	var normalized []int
	switch v := values.(type) {
	case map[int]struct{}:
		normalized = binValues(v)
	case []int:
		normalized = normalizeABAValues(v)
	}
	if len(normalized) == 1 {
		return abaSingleValueKey(normalized[0])
	}
	if len(normalized) == 2 {
		return "01"
	}
	return ""
}

func abaSingleValueKey(v int) string {
	if v == 0 {
		return "0"
	}
	return "1"
}

func abaValuesSubset(values []int, bin map[int]struct{}) bool {
	for _, v := range values {
		if _, ok := bin[v]; !ok {
			return false
		}
	}
	return len(values) > 0
}
