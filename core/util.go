package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func safeCacheComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	var out strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

func encodeInts(v []int) []byte {
	out := make([]byte, 8*len(v))
	for i, n := range v {
		binary.BigEndian.PutUint64(out[i*8:(i+1)*8], uint64(n))
	}
	return out
}

func sortedCopy(v []int) []int {
	cp := append([]int(nil), v...)
	sort.Ints(cp)
	return cp
}

func takeFirst(v []int, k int) []int {
	if k <= 0 {
		return nil
	}
	if len(v) <= k {
		return append([]int(nil), v...)
	}
	return append([]int(nil), v[:k]...)
}

func localOldNodes(cfg Config) []int {
	local := filterNodeIDs(cfg.LocalNodeIDs, cfg.OldCommittee)
	if len(local) == 0 {
		return sortedUnique(cfg.OldCommittee)
	}
	return local
}

func nodeSet(ids []int) map[int]struct{} {
	out := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func bytesEq(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func sortedUnique(v []int) []int {
	cp := sortedCopy(v)
	if len(cp) <= 1 {
		return cp
	}
	out := make([]int, 0, len(cp))
	last := cp[0] - 1
	for _, id := range cp {
		if len(out) == 0 || id != last {
			out = append(out, id)
			last = id
		}
	}
	return out
}
