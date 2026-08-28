package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	cvComponentCodewordDomain = "ARL-CV-sAPVSS/component-codeword"
	// Each independent GF(256) equation contributes eight soundness bits.
	cvComponentCodewordChecks = 16
)

var (
	cvGF256MulOnce  sync.Once
	cvGF256MulTable [256][256]byte
)

func cvInitGF256MulTable() {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			cvGF256MulTable[a][b] = cvGF256Mul(byte(a), byte(b))
		}
	}
}

// cvGF256Mul uses the x^8+x^4+x^3+x^2+1 polynomial used by the RS backend.
func cvGF256Mul(a, b byte) byte {
	var product byte
	for b != 0 {
		if b&1 != 0 {
			product ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return product
}

func cvComponentFingerprintCoefficients(root []byte, shardBytes int) ([]byte, error) {
	if len(root) != 32 || shardBytes <= 0 || shardBytes > cvMaxLeafWireBytes+8 {
		return nil, fmt.Errorf("invalid component codeword challenge")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(shardBytes))
	stream := deterministicStream(cvComponentCodewordDomain, root, encoded[:])
	coefficients := make([]byte, cvComponentCodewordChecks*shardBytes)
	stream.XORKeyStream(coefficients, coefficients)
	return coefficients, nil
}

func cvComponentShardFingerprint(payload, coefficients []byte) ([]byte, error) {
	if len(payload) == 0 || len(coefficients) != cvComponentCodewordChecks*len(payload) {
		return nil, fmt.Errorf("invalid component shard fingerprint input")
	}
	cvGF256MulOnce.Do(cvInitGF256MulTable)
	fingerprint := make([]byte, cvComponentCodewordChecks)
	for check := 0; check < cvComponentCodewordChecks; check++ {
		row := coefficients[check*len(payload) : (check+1)*len(payload)]
		var value byte
		for i, coefficient := range row {
			value ^= cvGF256MulTable[coefficient][payload[i]]
		}
		fingerprint[check] = value
	}
	return fingerprint, nil
}

func cvBuildComponentCodewordProof(root []byte, shards [][]byte, dataShards int) ([][]byte, error) {
	if len(shards) < dataShards || dataShards <= 0 || len(shards[0]) == 0 {
		return nil, fmt.Errorf("invalid component codeword proof input")
	}
	shardBytes := len(shards[0])
	coefficients, err := cvComponentFingerprintCoefficients(root, shardBytes)
	if err != nil {
		return nil, err
	}
	dataFingerprints := make([][]byte, dataShards)
	for i := 0; i < dataShards; i++ {
		if len(shards[i]) != shardBytes {
			return nil, fmt.Errorf("component codeword uses unequal shard lengths")
		}
		dataFingerprints[i], err = cvComponentShardFingerprint(shards[i], coefficients)
		if err != nil {
			return nil, err
		}
	}
	return dataFingerprints, nil
}

func cvComponentExpectedFingerprints(dispersal *cvComponentDispersal, totalShards int) ([][]byte, error) {
	if !cvValidComponentDispersalForRoster(dispersal, totalShards) {
		return nil, fmt.Errorf("invalid component codeword proof")
	}
	flat := make([]byte, 0, dispersal.dataShards*cvComponentCodewordChecks)
	for _, fingerprint := range dispersal.dataFingerprints {
		flat = append(flat, fingerprint...)
	}
	return cvErasureEncode(flat, dispersal.dataShards, totalShards)
}

func cvVerifyComponentCodewordShard(dispersal *cvComponentDispersal, totalShards int, shard *cvComponentShard) error {
	if shard == nil || len(shard.payload) != dispersal.shardBytes {
		return fmt.Errorf("component shard length does not match codeword proof")
	}
	coefficients, err := cvComponentFingerprintCoefficients(dispersal.root, dispersal.shardBytes)
	if err != nil {
		return err
	}
	actual, err := cvComponentShardFingerprint(shard.payload, coefficients)
	if err != nil {
		return err
	}
	expected, err := cvComponentExpectedFingerprints(dispersal, totalShards)
	if err != nil || shard.index < 0 || shard.index >= len(expected) ||
		!bytes.Equal(actual, expected[shard.index]) {
		return fmt.Errorf("CV-sAPVSS component shard is outside the committed RS codeword")
	}
	return nil
}

func cvEqualComponentDispersal(left, right *cvComponentDispersal) bool {
	if !cvValidComponentDispersal(left) || !cvValidComponentDispersal(right) ||
		left.dataShards != right.dataShards || left.shardBytes != right.shardBytes ||
		!bytes.Equal(left.nonce, right.nonce) || !bytes.Equal(left.payloadDigest, right.payloadDigest) ||
		!bytes.Equal(left.root, right.root) || len(left.dataFingerprints) != len(right.dataFingerprints) {
		return false
	}
	for i := range left.dataFingerprints {
		if !bytes.Equal(left.dataFingerprints[i], right.dataFingerprints[i]) {
			return false
		}
	}
	return true
}
