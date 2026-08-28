package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/reedsolomon"
)

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func digestDomain(domain string, sid string, root []byte) []byte {
	return hashBytes([]byte(domain), []byte{0}, []byte(sid), []byte{0}, root)
}

func pdCertificateDigest(domain, sid string, leader int, root []byte) []byte {
	var leaderWire [8]byte
	binary.BigEndian.PutUint64(leaderWire[:], uint64(leader))
	return hashBytes([]byte(domain), []byte{0}, []byte(sid), []byte{0}, leaderWire[:], []byte{0}, root)
}

func recoverThresholdCertificate(
	signer Signer, domain string, digest []byte, shares map[int][]byte, threshold int,
) ([]byte, error) {
	ts, ok := signer.(ThresholdSigner)
	if !ok || threshold <= 0 || ts.Threshold(domain) != threshold || len(shares) < threshold {
		return nil, fmt.Errorf("invalid %s threshold certificate input", domain)
	}
	certificate, err := ts.Recover(domain, digest, shares)
	if err != nil || !ts.VerifyRecovered(domain, digest, certificate) {
		return nil, fmt.Errorf("recover %s threshold certificate", domain)
	}
	return certificate, nil
}

func verifyThresholdCertificate(signer Signer, domain string, digest, certificate []byte, threshold int) bool {
	ts, ok := signer.(ThresholdSigner)
	return ok && threshold > 0 && ts.Threshold(domain) == threshold &&
		len(certificate) > 0 && ts.VerifyRecovered(domain, digest, certificate)
}

func packValue(v []byte) []byte {
	out := make([]byte, 8+len(v))
	binary.BigEndian.PutUint64(out[:8], uint64(len(v)))
	copy(out[8:], v)
	return out
}

func unpackValue(v []byte) ([]byte, error) {
	if len(v) < 8 {
		return nil, fmt.Errorf("packed value too short")
	}
	n := binary.BigEndian.Uint64(v[:8])
	if int(8+n) > len(v) {
		return nil, fmt.Errorf("packed value length mismatch")
	}
	out := make([]byte, n)
	copy(out, v[8:8+n])
	return out, nil
}

func erasureEncodeValue(v []byte, k int, n int) ([][]byte, error) {
	if k <= 0 || n <= 0 || k > n {
		return nil, fmt.Errorf("invalid erasure params")
	}
	// When there are no parity shards (n == k, i.e. f == 0), Reed-Solomon
	// is not applicable. Replicate the full packed value into every shard
	// so that any single shard is sufficient for reconstruction.
	if n == k {
		payload := packValue(v)
		shards := make([][]byte, n)
		for i := range shards {
			shards[i] = make([]byte, len(payload))
			copy(shards[i], payload)
		}
		return shards, nil
	}
	enc, err := reedsolomon.New(k, n-k)
	if err != nil {
		return nil, err
	}
	payload := packValue(v)
	shards, err := enc.Split(payload)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func erasureDecodeValue(shards [][]byte, k int, n int) ([]byte, error) {
	if len(shards) != n {
		return nil, fmt.Errorf("invalid shard count")
	}
	// No-parity path: every shard is a full copy of the packed value.
	// Return the first non-nil one.
	if n == k {
		for i := range shards {
			if shards[i] != nil {
				return unpackValue(shards[i])
			}
		}
		return nil, fmt.Errorf("all shards missing")
	}
	enc, err := reedsolomon.New(k, n-k)
	if err != nil {
		return nil, err
	}
	work := make([][]byte, len(shards))
	var shardLen int
	for i := range shards {
		if shards[i] != nil {
			work[i] = append([]byte(nil), shards[i]...)
			if shardLen == 0 {
				shardLen = len(shards[i])
			}
		}
	}
	if shardLen == 0 {
		return nil, fmt.Errorf("all shards missing")
	}
	if err := enc.Reconstruct(work); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := enc.Join(&buf, work, shardLen*k); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(&buf)
	if err != nil {
		return nil, err
	}
	return unpackValue(raw)
}

func leafHash(v []byte) []byte {
	return hashBytes([]byte{0}, v)
}

func nodeHash(l []byte, r []byte) []byte {
	return hashBytes([]byte{1}, l, r)
}

func buildMerkle(stripes [][]byte) ([]byte, []merkleBranch) {
	n := len(stripes)
	branches := make([]merkleBranch, n)
	if n == 0 {
		return hashBytes(nil), branches
	}
	level := make([][]byte, n)
	for i := 0; i < n; i++ {
		level[i] = leafHash(stripes[i])
		branches[i] = merkleBranch{Index: i}
	}
	indexes := make([]int, n)
	for i := range indexes {
		indexes[i] = i
	}

	for len(level) > 1 {
		padded := level
		if len(padded)%2 == 1 {
			padded = append(append([][]byte(nil), padded...), padded[len(padded)-1])
		}
		for i := 0; i < n; i++ {
			pos := indexes[i]
			sibling := pos ^ 1
			if sibling >= len(padded) {
				sibling = len(padded) - 1
			}
			branches[i].Siblings = append(branches[i].Siblings, append([]byte(nil), padded[sibling]...))
			indexes[i] = pos / 2
		}
		next := make([][]byte, 0, len(padded)/2)
		for i := 0; i < len(padded); i += 2 {
			next = append(next, nodeHash(padded[i], padded[i+1]))
		}
		level = next
	}
	return append([]byte(nil), level[0]...), branches
}

func verifyMerkle(stripe []byte, root []byte, branch merkleBranch) bool {
	cur := leafHash(stripe)
	idx := branch.Index
	for _, sib := range branch.Siblings {
		if idx%2 == 0 {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
		idx /= 2
	}
	return bytes.Equal(cur, root)
}
