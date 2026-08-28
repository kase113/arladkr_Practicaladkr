// bitset.go — 位集工具（复用自 adkr-go）
package core

import "sort"

func encodeSet(universe []int, set []int) []byte {
	pos := make(map[int]int, len(universe))
	for i, id := range universe {
		pos[id] = i
	}
	n := len(universe)
	out := make([]byte, (n+7)/8)
	for _, id := range set {
		i, ok := pos[id]
		if !ok {
			continue
		}
		out[i/8] |= 1 << uint(i%8)
	}
	return out
}

func decodeSet(universe []int, payload []byte) []int {
	out := make([]int, 0, len(universe))
	for i := 0; i < len(universe); i++ {
		if i/8 >= len(payload) {
			break
		}
		if (payload[i/8] & (1 << uint(i%8))) != 0 {
			out = append(out, universe[i])
		}
	}
	return out
}

func stableFirst(set []int, k int) []int {
	if k <= 0 || len(set) == 0 {
		return nil
	}
	cp := make([]int, len(set))
	copy(cp, set)
	sort.Ints(cp)
	if len(cp) > k {
		cp = cp[:k]
	}
	return cp
}
