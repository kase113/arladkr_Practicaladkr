package core

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvAPDBInstanceDomain  = "ARL-CV-sAPVSS/v2-scalar-group/apdb-instance"
	cvAPDBStoredDomain    = "ARL-CV-sAPVSS/v2-scalar-group/apdb-stored"
	cvAPDBShardDomain     = "ARL-CV-sAPVSS/v2-scalar-group/apdb-shard"
	cvAPDBNodeDomain      = "ARL-CV-sAPVSS/v2-scalar-group/apdb-node"
	cvAPDBLockWireDomain  = "ARL-CV-sAPVSS/v2-scalar-group/apdb-lock"
	cvAPDBStoreWireDomain = "ARL-CV-sAPVSS/v2-scalar-group/apdb-store"
)

// cvAPDBLockScalar is the compact public certificate of an immutable APDB
// instance. Individual holder identities and signature shares never enter it.
type cvAPDBLockScalar struct {
	InstanceDigest []byte
	Root           []byte
	Certificate    []byte
	// canonicalWire is set only after strict decoding and byte equality.
	canonicalWire []byte
}

type cvAPDBStoreScalar struct {
	InstanceDigest []byte
	Root           []byte
	Index          int
	Shard          []byte
	Siblings       [][]byte
}

type cvAPDBEncodedScalar struct {
	instanceDigest []byte
	root           []byte
	dataShards     int
	totalShards    int
	shardBytes     int
	stores         []cvAPDBStoreScalar
}

func cvAPDBInstanceDigestScalar(label string, parts ...[]byte) ([]byte, error) {
	if label == "" {
		return nil, fmt.Errorf("empty CV V2 APDB instance label")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(label))
	for _, part := range parts {
		if err := cvWriteBytes(&wire, part); err != nil {
			return nil, err
		}
	}
	return hashBytes([]byte(cvAPDBInstanceDomain), wire.Bytes()), nil
}

func cvAPDBStoredStatementScalar(instanceDigest, root []byte) ([]byte, error) {
	if len(instanceDigest) != 32 || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB stored statement")
	}
	return hashBytes([]byte(cvAPDBStoredDomain), instanceDigest, root), nil
}

func cvAPDBEncodeScalar(instanceDigest, payload []byte, dataShards, totalShards, maximumPayload int) (*cvAPDBEncodedScalar, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload ||
		dataShards <= 0 || totalShards < dataShards {
		return nil, fmt.Errorf("invalid CV V2 APDB encoding parameters")
	}
	shardBytes := (8 + len(payload) + dataShards - 1) / dataShards
	return cvAPDBEncodeSizedScalar(instanceDigest, payload, dataShards, totalShards, shardBytes, maximumPayload)
}

func cvAPDBEncodeSizedScalar(
	instanceDigest, payload []byte, dataShards, totalShards, shardBytes, maximumPayload int,
) (*cvAPDBEncodedScalar, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload ||
		dataShards <= 0 || totalShards < dataShards || shardBytes <= 0 ||
		8+len(payload) > dataShards*shardBytes {
		return nil, fmt.Errorf("invalid CV V2 fixed-size APDB encoding parameters")
	}
	packed := make([]byte, dataShards*shardBytes)
	binary.BigEndian.PutUint64(packed[:8], uint64(len(payload)))
	copy(packed[8:], payload)
	shards, err := cvErasureEncode(packed, dataShards, totalShards)
	if err != nil {
		return nil, fmt.Errorf("encode CV V2 APDB payload: %w", err)
	}
	if len(shards) != totalShards || len(shards) == 0 || len(shards[0]) == 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB encoded shard set")
	}
	root, branches := cvAPDBBuildMerkleScalar(instanceDigest, shards)
	encoded := &cvAPDBEncodedScalar{
		instanceDigest: append([]byte(nil), instanceDigest...), root: root,
		dataShards: dataShards, totalShards: totalShards, shardBytes: len(shards[0]),
		stores: make([]cvAPDBStoreScalar, totalShards),
	}
	for i := range shards {
		encoded.stores[i] = cvAPDBStoreScalar{
			InstanceDigest: append([]byte(nil), instanceDigest...), Root: append([]byte(nil), root...), Index: i,
			Shard: append([]byte(nil), shards[i]...), Siblings: cvCloneByteSlices(branches[i]),
		}
	}
	return encoded, nil
}

func cvAPDBBuildMerkleScalar(instanceDigest []byte, shards [][]byte) ([]byte, [][][]byte) {
	levels := [][][]byte{make([][]byte, len(shards))}
	for i := range shards {
		levels[0][i] = cvAPDBShardHashScalar(instanceDigest, i, shards[i])
	}
	for len(levels[len(levels)-1]) > 1 {
		level := levels[len(levels)-1]
		padded := level
		if len(level)%2 == 1 {
			padded = append(append([][]byte(nil), level...), level[len(level)-1])
		}
		next := make([][]byte, 0, len(padded)/2)
		for i := 0; i < len(padded); i += 2 {
			next = append(next, hashBytes([]byte(cvAPDBNodeDomain), padded[i], padded[i+1]))
		}
		levels = append(levels, next)
	}
	branches := make([][][]byte, len(shards))
	for i := range shards {
		index := i
		for depth := 0; depth < len(levels)-1; depth++ {
			level := levels[depth]
			sibling := index ^ 1
			if sibling >= len(level) {
				sibling = len(level) - 1
			}
			branches[i] = append(branches[i], append([]byte(nil), level[sibling]...))
			index /= 2
		}
	}
	return append([]byte(nil), levels[len(levels)-1][0]...), branches
}

func cvAPDBShardHashScalar(instanceDigest []byte, index int, shard []byte) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(index))
	return hashBytes([]byte(cvAPDBShardDomain), instanceDigest, encoded[:], shard)
}

func cvVerifyAPDBStoreScalar(store *cvAPDBStoreScalar, totalShards, shardBytes int) error {
	if store == nil || len(store.InstanceDigest) != 32 || len(store.Root) != 32 || store.Index < 0 ||
		store.Index >= totalShards || shardBytes <= 0 || len(store.Shard) != shardBytes {
		return fmt.Errorf("invalid CV V2 APDB store")
	}
	wantDepth := cvAPDBMerkleDepth(totalShards)
	if len(store.Siblings) != wantDepth {
		return fmt.Errorf("invalid CV V2 APDB Merkle branch depth")
	}
	digest := cvAPDBShardHashScalar(store.InstanceDigest, store.Index, store.Shard)
	index := store.Index
	for _, sibling := range store.Siblings {
		if len(sibling) != 32 {
			return fmt.Errorf("invalid CV V2 APDB Merkle sibling")
		}
		if index%2 == 0 {
			digest = hashBytes([]byte(cvAPDBNodeDomain), digest, sibling)
		} else {
			digest = hashBytes([]byte(cvAPDBNodeDomain), sibling, digest)
		}
		index /= 2
	}
	if !bytes.Equal(digest, store.Root) {
		return fmt.Errorf("CV V2 APDB store root mismatch")
	}
	return nil
}

func cvAPDBMerkleDepth(totalShards int) int {
	depth := 0
	for totalShards > 1 {
		depth++
		totalShards = (totalShards + 1) / 2
	}
	return depth
}

func cvNewAPDBLockScalar(encoded *cvAPDBEncodedScalar, certificate []byte) (*cvAPDBLockScalar, error) {
	if encoded == nil || len(encoded.instanceDigest) != 32 || len(encoded.root) != 32 || len(certificate) == 0 ||
		len(certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB lock")
	}
	return &cvAPDBLockScalar{
		InstanceDigest: append([]byte(nil), encoded.instanceDigest...), Root: append([]byte(nil), encoded.root...),
		Certificate: append([]byte(nil), certificate...),
	}, nil
}

func cvVerifyAPDBLockScalar(lock *cvAPDBLockScalar, signer *tblsThresholdSigner) error {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || len(lock.Certificate) == 0 ||
		len(lock.Certificate) > cvMaxComponentSignatureBytes || !cvScalarSignerHasRole(signer, cvScalarRoleAPDB) {
		return fmt.Errorf("invalid CV V2 APDB lock")
	}
	statement, err := cvAPDBStoredStatementScalar(lock.InstanceDigest, lock.Root)
	if err != nil || !signer.VerifyRecovered(cvAPDBStoredDomain, statement, lock.Certificate) {
		return fmt.Errorf("invalid CV V2 APDB lock certificate")
	}
	return nil
}

func cvRecoverAPDBScalar(
	lock *cvAPDBLockScalar, stores []cvAPDBStoreScalar, dataShards, totalShards, shardBytes, maximumPayload int,
	bindingCheck func([]byte) error,
) ([]byte, error) {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || dataShards <= 0 ||
		totalShards < dataShards || shardBytes <= 0 || maximumPayload <= 0 || len(stores) < dataShards {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery input")
	}
	shards := make([][]byte, totalShards)
	seen := make(map[int]struct{}, len(stores))
	for i := range stores {
		store := &stores[i]
		if !bytes.Equal(store.InstanceDigest, lock.InstanceDigest) || !bytes.Equal(store.Root, lock.Root) ||
			cvVerifyAPDBStoreScalar(store, totalShards, shardBytes) != nil {
			return nil, fmt.Errorf("invalid CV V2 APDB recovery store")
		}
		if _, duplicate := seen[store.Index]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 APDB recovery store index")
		}
		seen[store.Index] = struct{}{}
		shards[store.Index] = append([]byte(nil), store.Shard...)
	}
	if len(seen) < dataShards {
		return nil, fmt.Errorf("insufficient CV V2 APDB recovery stores")
	}
	packed, err := cvErasureDecode(shards, dataShards)
	if err != nil {
		return nil, fmt.Errorf("decode CV V2 APDB payload: %w", err)
	}
	if len(packed) < 8 {
		return nil, fmt.Errorf("truncated CV V2 APDB payload")
	}
	length := binary.BigEndian.Uint64(packed[:8])
	if length == 0 || length > uint64(len(packed)-8) || length > uint64(maximumPayload) {
		return nil, fmt.Errorf("invalid recovered CV V2 APDB payload length")
	}
	payload := append([]byte(nil), packed[8:8+int(length)]...)
	reencoded, err := cvAPDBEncodeSizedScalar(
		lock.InstanceDigest, payload, dataShards, totalShards, shardBytes, maximumPayload,
	)
	if err != nil || !bytes.Equal(reencoded.root, lock.Root) {
		return nil, fmt.Errorf("CV V2 APDB deterministic re-encoding root mismatch")
	}
	if bindingCheck != nil {
		if err := bindingCheck(payload); err != nil {
			return nil, fmt.Errorf("CV V2 APDB binding check: %w", err)
		}
	}
	return payload, nil
}

func cvAPDBLockScalarCanonicalBytes(lock *cvAPDBLockScalar) ([]byte, error) {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || len(lock.Certificate) == 0 ||
		len(lock.Certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB lock")
	}
	if len(lock.canonicalWire) != 0 {
		return lock.canonicalWire, nil
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBLockWireDomain))
	_ = cvWriteBytes(&wire, lock.InstanceDigest)
	_ = cvWriteBytes(&wire, lock.Root)
	_ = cvWriteBytes(&wire, lock.Certificate)
	return wire.Bytes(), nil
}

func cvDecodeAPDBLockScalar(wire []byte) (*cvAPDBLockScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBLockWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBLockWireDomain)) {
		return nil, fmt.Errorf("invalid CV V2 APDB lock domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil || len(instanceDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock root")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock certificate")
	}
	lock := &cvAPDBLockScalar{InstanceDigest: instanceDigest, Root: root, Certificate: certificate}
	canonical, err := cvAPDBLockScalarCanonicalBytes(lock)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 APDB lock")
	}
	lock.canonicalWire = canonical
	return lock, nil
}

func cvAPDBStoreScalarCanonicalBytes(store *cvAPDBStoreScalar, totalShards, shardBytes int) ([]byte, error) {
	if err := cvVerifyAPDBStoreScalar(store, totalShards, shardBytes); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBStoreWireDomain))
	_ = cvWriteBytes(&wire, store.InstanceDigest)
	_ = cvWriteBytes(&wire, store.Root)
	if err := cvWriteUint32(&wire, store.Index); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, store.Shard)
	if err := cvWriteUint32(&wire, len(store.Siblings)); err != nil {
		return nil, err
	}
	for _, sibling := range store.Siblings {
		_ = cvWriteBytes(&wire, sibling)
	}
	return wire.Bytes(), nil
}

func cvDecodeAPDBStoreScalar(wire []byte, totalShards, shardBytes int) (*cvAPDBStoreScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBStoreWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBStoreWireDomain)) {
		return nil, fmt.Errorf("invalid CV V2 APDB store domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil || len(instanceDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB store instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB store root")
	}
	index, err := r.uint32()
	if err != nil || index < 0 || index >= totalShards {
		return nil, fmt.Errorf("invalid CV V2 APDB store index")
	}
	shard, err := r.bytes(shardBytes)
	if err != nil || len(shard) != shardBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB store shard")
	}
	depth, err := r.uint32()
	if err != nil || depth != cvAPDBMerkleDepth(totalShards) {
		return nil, fmt.Errorf("invalid CV V2 APDB store branch depth")
	}
	siblings := make([][]byte, depth)
	for i := range siblings {
		siblings[i], err = r.bytes(32)
		if err != nil || len(siblings[i]) != 32 {
			return nil, fmt.Errorf("invalid CV V2 APDB store sibling")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 APDB store bytes")
	}
	store := &cvAPDBStoreScalar{InstanceDigest: instanceDigest, Root: root, Index: index, Shard: shard, Siblings: siblings}
	// The parser consumed the fixed domain, digest, root, index, exact shard,
	// exact Merkle depth, all 32-byte siblings, and EOF. Verify the authenticated
	// root directly; re-serializing the full shard/branch solely to compare the
	// same deterministic framing adds an allocation on every response.
	if err := cvVerifyAPDBStoreScalar(store, totalShards, shardBytes); err != nil {
		return nil, err
	}
	return store, nil
}

func cvCloneByteSlices(input [][]byte) [][]byte {
	out := make([][]byte, len(input))
	for i := range input {
		out[i] = append([]byte(nil), input[i]...)
	}
	return out
}

const (
	cvAPDBPayloadWireDomain           = "ARL-CV-sAPVSS/v2-scalar-group/apdb-recover-payload"
	cvAPDBPayloadCompressedWireDomain = "ARL-CV-sAPVSS/v2-scalar-group/apdb-recover-payload-deflate-v1"
)

type cvAPDBPayloadResponseScalar struct {
	InstanceDigest []byte
	Payload        []byte
	// Hints optionally carries the uncompressed forms of every deferred
	// point the consumer's leaf decode reads, in wire order. Each entry is
	// authenticated by exact recompression against the signed payload bytes,
	// so the attachment trades bytes for square roots and never adds a trust
	// assumption; responses without it decode exactly as before.
	Hints []byte
}

func cvAPDBPayloadResponseScalarCanonicalBytes(response *cvAPDBPayloadResponseScalar) ([]byte, error) {
	if response == nil || len(response.InstanceDigest) != 32 || len(response.Payload) == 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response")
	}
	if len(response.Hints) > 0 && len(response.Hints)%bls12381.SizeOfG1AffineUncompressed != 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response hints framing")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBPayloadWireDomain))
	_ = cvWriteBytes(&wire, response.InstanceDigest)
	_ = cvWriteBytes(&wire, response.Payload)
	if len(response.Hints) > 0 {
		_ = cvWriteBytes(&wire, response.Hints)
	}
	return wire.Bytes(), nil
}

func cvAPDBPayloadResponseScalarTransportBytes(response *cvAPDBPayloadResponseScalar) ([]byte, error) {
	legacy, err := cvAPDBPayloadResponseScalarCanonicalBytes(response)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err = writer.Write(response.Payload); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	// Keep the legacy representation when compression does not pay for its
	// domain, original-length field, and framing overhead.
	if compressed.Len()+len(cvAPDBPayloadCompressedWireDomain)+16 >= len(response.Payload) {
		return legacy, nil
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBPayloadCompressedWireDomain))
	_ = cvWriteBytes(&wire, response.InstanceDigest)
	if err := cvWriteUint32(&wire, len(response.Payload)); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, compressed.Bytes())
	if len(response.Hints) > 0 {
		_ = cvWriteBytes(&wire, response.Hints)
	}
	return wire.Bytes(), nil
}

func cvDecodeAPDBPayloadResponseScalar(wire []byte, maximumPayload int) (*cvAPDBPayloadResponseScalar, error) {
	if maximumPayload <= 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response limit")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBPayloadCompressedWireDomain))
	compressed := bytes.Equal(domain, []byte(cvAPDBPayloadCompressedWireDomain))
	if err != nil || (!compressed && !bytes.Equal(domain, []byte(cvAPDBPayloadWireDomain))) {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response instance")
	}
	var payload []byte
	if compressed {
		originalLength, lengthErr := r.uint32()
		if lengthErr != nil || originalLength <= 0 || originalLength > maximumPayload {
			return nil, fmt.Errorf("invalid CV V2 APDB compressed payload length")
		}
		compressedLimit := maximumPayload + maximumPayload/16 + 1024
		compressedPayload, readErr := r.bytes(compressedLimit)
		if readErr != nil || len(compressedPayload) == 0 {
			return nil, fmt.Errorf("invalid CV V2 APDB compressed payload body")
		}
		reader := flate.NewReader(bytes.NewReader(compressedPayload))
		payload, err = io.ReadAll(io.LimitReader(reader, int64(maximumPayload)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || len(payload) != originalLength {
			return nil, fmt.Errorf("invalid CV V2 APDB compressed payload")
		}
	} else {
		payload, err = r.bytes(maximumPayload)
		if err != nil || len(payload) == 0 {
			return nil, fmt.Errorf("invalid CV V2 APDB payload response body")
		}
	}
	var hints []byte
	if r.reader.Len() > 0 {
		hints, err = r.bytes(cvMaxPayloadHintsBytesScalar(maximumPayload))
		if err != nil || r.reader.Len() != 0 ||
			len(hints)%bls12381.SizeOfG1AffineUncompressed != 0 {
			return nil, fmt.Errorf("invalid CV V2 APDB payload response hints")
		}
	}
	return &cvAPDBPayloadResponseScalar{InstanceDigest: instanceDigest, Payload: payload, Hints: hints}, nil
}
