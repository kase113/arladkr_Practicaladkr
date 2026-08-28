package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

func selectByThresholdCoin(decided []int, kappa int, coinSignature, coinInputDigest []byte) ([]int, error) {
	if len(decided) == 0 {
		return nil, fmt.Errorf("empty decided set")
	}
	if kappa <= 0 || kappa > len(decided) {
		return nil, fmt.Errorf("invalid kappa=%d for decided set size=%d", kappa, len(decided))
	}
	if len(coinSignature) == 0 || len(coinInputDigest) != sha256.Size {
		return nil, fmt.Errorf("threshold coin requires a recovered signature and canonical input digest")
	}
	canonical := append([]int(nil), decided...)
	sort.Ints(canonical)
	for i := 1; i < len(canonical); i++ {
		if canonical[i-1] == canonical[i] {
			return nil, fmt.Errorf("decided set contains duplicate dealer %d", canonical[i])
		}
	}
	h := sha256.New()
	h.Write([]byte("PADKR-THRESHOLD-COIN-SELECTION-V2"))
	h.Write(coinInputDigest)
	h.Write(coinSignature)
	var seed [sha256.Size]byte
	copy(seed[:], h.Sum(nil))
	return shuffleBySeed(canonical, kappa, seed), nil
}

func shuffleBySeed(in []int, kappa int, seed [32]byte) []int {
	cp := append([]int(nil), in...)
	for i := len(cp) - 1; i > 0; i-- {
		var mix [8]byte
		binary.BigEndian.PutUint64(mix[:], uint64(i))
		h := sha256.New()
		h.Write(seed[:])
		h.Write(mix[:])
		sum := sha256.Sum256(h.Sum(nil))
		j := int(binary.BigEndian.Uint64(sum[:8]) % uint64(i+1))
		cp[i], cp[j] = cp[j], cp[i]
	}
	out := append([]int(nil), cp[:kappa]...)
	sort.Ints(out)
	return out
}
