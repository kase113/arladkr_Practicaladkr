package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
)

func (m *DumboMVBA) makeSharedCoin(
	ctx context.Context,
	sid string,
	tag ProtocolTag,
	round int,
	recv <-chan ReceivedMessage,
) func(nonce string) (int, error) {
	return func(nonce string) (int, error) {
		n := m.cfg.N
		threshold := m.cfg.F + 1
		ts, hasTS := m.signer.(ThresholdSigner)
		if hasTS {
			threshold = ts.Threshold("EQ_COIN_SHARE")
		}
		dig := hashBytes([]byte("EQ_COIN"), []byte(sid), []byte{0}, []byte(nonce))

		share, err := m.signer.Sign("EQ_COIN_SHARE", dig)
		if err != nil {
			return 0, err
		}
		for i := 0; i < n; i++ {
			_ = m.net.Send(i, ProtocolMessage{
				Tag:    tag,
				Round:  round,
				Leader: 0,
				Body: coinShareMsg{
					SID:   sid,
					Nonce: nonce,
					Share: append([]byte(nil), share...),
				},
			})
		}

		shares := map[int][]byte{
			m.cfg.ID: append([]byte(nil), share...),
		}
		for {
			if len(shares) >= threshold {
				if hasTS && m.cfg.EquivalentCoinMode != "deterministic" {
					recovered, recErr := ts.Recover("EQ_COIN_SHARE", dig, shares)
					if recErr != nil {
						return 0, fmt.Errorf("recover equivalent threshold coin: %w", recErr)
					}
					if !ts.VerifyRecovered("EQ_COIN_SHARE", dig, recovered) {
						return 0, fmt.Errorf("verify recovered equivalent threshold coin")
					}
					h := hashBytes([]byte("EQ_COIN_REC"), []byte(sid), []byte(nonce), recovered)
					return int(binary.BigEndian.Uint64(h[:8]) & 0x7fffffff), nil
				}
				return deriveCoinValue(m.cfg.EquivalentCoinMode, sid, nonce, shares), nil
			}
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case in := <-recv:
				msg, ok := in.Msg.Body.(coinShareMsg)
				if !ok {
					continue
				}
				if msg.SID != sid || msg.Nonce != nonce {
					continue
				}
				if _, seen := shares[in.From]; seen {
					continue
				}
				if !m.signer.Verify(in.From, "EQ_COIN_SHARE", dig, msg.Share) {
					continue
				}
				shares[in.From] = append([]byte(nil), msg.Share...)
			}
		}
	}
}

func deriveCoinValue(mode string, sid string, nonce string, shares map[int][]byte) int {
	if mode == "" {
		mode = "signature"
	}
	if mode == "deterministic" {
		h := hashBytes([]byte("EQ_COIN_DET"), []byte(sid), []byte(nonce))
		return int(binary.BigEndian.Uint64(h[:8]) & 0x7fffffff)
	}
	keys := make([]int, 0, len(shares))
	for k := range shares {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	buf := make([]byte, 0, len(keys)*64)
	for _, k := range keys {
		buf = append(buf, []byte(fmt.Sprintf("%d:", k))...)
		buf = append(buf, shares[k]...)
	}
	h := hashBytes([]byte("EQ_COIN_SIG"), []byte(sid), []byte(nonce), buf)
	return int(binary.BigEndian.Uint64(h[:8]) & 0x7fffffff)
}
