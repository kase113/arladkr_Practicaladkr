package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/reedsolomon"
)

func packRecoverValue(v []byte) []byte {
	out := make([]byte, 8+len(v))
	binary.BigEndian.PutUint64(out[:8], uint64(len(v)))
	copy(out[8:], v)
	return out
}

func unpackRecoverValue(v []byte) ([]byte, error) {
	if len(v) < 8 {
		return nil, fmt.Errorf("packed recover value too short")
	}
	n := binary.BigEndian.Uint64(v[:8])
	if int(8+n) > len(v) {
		return nil, fmt.Errorf("packed recover value length mismatch")
	}
	out := make([]byte, n)
	copy(out, v[8:8+n])
	return out, nil
}

func recoverEncodeValue(v []byte, k int, n int) ([][]byte, error) {
	if k <= 0 || n <= 0 || k > n {
		return nil, fmt.Errorf("invalid recover erasure params")
	}
	if n == k {
		payload := packRecoverValue(v)
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
	payload := packRecoverValue(v)
	shards, err := enc.Split(payload)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func recoverDecodeValue(shards map[int][]byte, k int, n int) ([]byte, error) {
	if len(shards) < k {
		return nil, fmt.Errorf("insufficient recover shards: have=%d need=%d", len(shards), k)
	}
	work := make([][]byte, n)
	for idx, shard := range shards {
		if idx < 0 || idx >= n || shard == nil {
			continue
		}
		work[idx] = append([]byte(nil), shard...)
	}
	if n == k {
		for i := range work {
			if work[i] != nil {
				return unpackRecoverValue(work[i])
			}
		}
		return nil, fmt.Errorf("all recover shards missing")
	}
	enc, err := reedsolomon.New(k, n-k)
	if err != nil {
		return nil, err
	}
	if err := enc.Reconstruct(work); err != nil {
		return nil, err
	}
	var shardLen int
	for i := range work {
		if work[i] != nil {
			shardLen = len(work[i])
			break
		}
	}
	if shardLen == 0 {
		return nil, fmt.Errorf("all recover shards missing after reconstruct")
	}
	var buf bytes.Buffer
	if err := enc.Join(&buf, work, shardLen*k); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(&buf)
	if err != nil {
		return nil, err
	}
	return unpackRecoverValue(raw)
}
