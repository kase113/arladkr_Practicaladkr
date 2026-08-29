package core

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	cvComponentDescriptorDomain    = "ARL-CV-sAPVSS/component-descriptor-certificate/v2"
	cvComponentStatementDomain     = "ARL-CV-sAPVSS/component-statement/v2"
	cvComponentPayloadDomain       = "ARL-CV-sAPVSS/component-payload"
	cvComponentShardDomain         = "ARL-CV-sAPVSS/component-shard"
	cvComponentShardNodeDomain     = "ARL-CV-sAPVSS/component-shard-node"
	cvComponentShardArtifactDomain = "ARL-CV-sAPVSS/component-shard-artifact"
	cvComponentLockSignatureDomain = "RL_CV_COMPONENT_LOCK"
	cvMaxComponentSignatureBytes   = 1 << 20
)

// cvComponentDispersal commits the RS shards and their codeword checks.
type cvComponentDispersal struct {
	nonce              []byte
	dataShards         int
	shardBytes         int
	payloadDigest      []byte
	semanticCommitment []byte
	root               []byte
	dataFingerprints   [][]byte
}

type cvComponentShard struct {
	index    int
	payload  []byte
	siblings [][]byte
}

type cvComponentShardArtifact struct {
	dealer     int
	leafDigest []byte
	dispersal  cvComponentDispersal
	shard      cvComponentShard
}

// cvComponentDescriptorCanonicalBytes encodes the certificate-only descriptor.
func cvComponentDescriptorCanonicalBytes(descriptor *cvComponentDescriptor) ([]byte, error) {
	if descriptor == nil || descriptor.dealer < 0 || len(descriptor.leafDigest) != 32 ||
		!cvValidComponentDispersal(&descriptor.dispersal) || len(descriptor.certificate) == 0 ||
		len(descriptor.certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component descriptor")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentDescriptorDomain))
	cvWriteUint64(&wire, uint64(descriptor.dealer))
	_ = cvWriteBytes(&wire, descriptor.leafDigest)
	if err := cvWriteComponentDispersal(&wire, &descriptor.dispersal); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, descriptor.certificate)
	return wire.Bytes(), nil
}

func cvDecodeComponentDescriptor(wire []byte, oldNodes []int) (*cvComponentDescriptor, error) {
	oldOrder := sortedUnique(oldNodes)
	return cvDecodeComponentDescriptorWithRoster(wire, oldNodes, nodeSet(oldOrder))
}

// cvDecodeComponentDescriptorWithRoster is the batch form used when the
// caller already built the immutable old-committee membership set.
func cvDecodeComponentDescriptorWithRoster(
	wire []byte, oldNodes []int, oldMembers map[int]struct{},
) (*cvComponentDescriptor, error) {
	if len(wire) == 0 || len(oldNodes) == 0 || len(oldMembers) == 0 {
		return nil, fmt.Errorf("invalid expected compact CV-sAPVSS component descriptor")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentDescriptorDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentDescriptorDomain)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component descriptor domain")
	}
	dealerWire, err := r.uint64()
	if err != nil || dealerWire > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component dealer")
	}
	dealer := int(dealerWire)
	if _, ok := oldMembers[dealer]; !ok {
		return nil, fmt.Errorf("compact CV-sAPVSS component dealer outside old roster")
	}
	leafDigest, err := r.bytes(32)
	if err != nil || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component leaf digest")
	}
	dispersal, err := cvReadComponentDispersal(r)
	if err != nil || !cvValidComponentDispersalForRoster(dispersal, len(oldNodes)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component dispersal")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component certificate")
	}
	// cvWireReader.bytes returns owned slices, so transferring them avoids a
	// second copy while preserving isolation from the caller's wire buffer.
	descriptor := &cvComponentDescriptor{
		dealer: dealer, leafDigest: leafDigest, dispersal: *dispersal, certificate: certificate,
	}
	canonical, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV-sAPVSS component descriptor")
	}
	return descriptor, nil
}

func cvValidateNetworkComponentDescriptor(cfg Config, descriptor *cvComponentDescriptor) error {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return err
	}
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil || c.runtime.lockSigner == nil {
		return fmt.Errorf("CV-sAPVSS component lock signer is unavailable")
	}
	wire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		return err
	}
	if _, err := cvDecodeComponentDescriptor(wire, c.OldCommittee); err != nil {
		return err
	}
	return cvValidateDecodedNetworkComponentDescriptor(&c, descriptor)
}

// cvValidateDecodedNetworkComponentDescriptor verifies a descriptor whose
// canonical wire form and roster-bound shape were already checked by the
// caller. c must have passed configuration and runtime validation.
func cvValidateDecodedNetworkComponentDescriptor(c *Config, descriptor *cvComponentDescriptor) error {
	if c == nil || c.runtime == nil || c.runtime.lockSigner == nil {
		return fmt.Errorf("CV-sAPVSS component lock signer is unavailable")
	}
	statement, err := cvComponentStatementDigest(descriptor.dealer, descriptor.leafDigest, &descriptor.dispersal)
	if err != nil {
		return err
	}
	if !c.runtime.lockSigner.VerifyRecovered(cvComponentLockSignatureDomain, statement, descriptor.certificate) {
		return fmt.Errorf("invalid compact CV-sAPVSS component lock certificate")
	}
	return nil
}

type cvComponentDescriptor struct {
	dealer      int
	leafDigest  []byte
	dispersal   cvComponentDispersal
	certificate []byte
}

func cvComponentLeafPayloadDigest(wire []byte) []byte {
	if apvssHasLeafWireDomain(wire) {
		return hashBytes([]byte(apvssLeafDigestDomain), wire)
	}
	return hashBytes([]byte(cvLeafDigestDomain), wire)
}

func cvComponentStatementDigest(dealer int, leafDigest []byte, dispersal *cvComponentDispersal) ([]byte, error) {
	wire, err := cvComponentStatementCanonicalBytes(dealer, leafDigest, dispersal)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvComponentStatementDomain), wire), nil
}

func cvComponentStatementCanonicalBytes(dealer int, leafDigest []byte, dispersal *cvComponentDispersal) ([]byte, error) {
	if dealer < 0 || len(leafDigest) != 32 || !cvValidComponentDispersal(dispersal) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentStatementDomain)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(dealer))
	if err := cvWriteBytes(&wire, leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteComponentDispersal(&wire, dispersal); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvValidComponentDispersal(dispersal *cvComponentDispersal) bool {
	if dispersal == nil || len(dispersal.nonce) != 32 || dispersal.dataShards <= 0 ||
		dispersal.shardBytes <= 0 || dispersal.shardBytes > cvMaxLeafWireBytes+8 ||
		len(dispersal.payloadDigest) != 32 || !cvValidLeafSemanticCommitment(dispersal.semanticCommitment) ||
		len(dispersal.root) != 32 ||
		len(dispersal.dataFingerprints) != dispersal.dataShards {
		return false
	}
	for _, fingerprint := range dispersal.dataFingerprints {
		if len(fingerprint) != cvComponentCodewordChecks {
			return false
		}
	}
	return true
}

func cvValidComponentDispersalForRoster(dispersal *cvComponentDispersal, totalShards int) bool {
	return totalShards > 0 && cvValidComponentDispersal(dispersal) && dispersal.dataShards <= totalShards
}

func cvWriteComponentDispersal(wire *bytes.Buffer, dispersal *cvComponentDispersal) error {
	if !cvValidComponentDispersal(dispersal) {
		return fmt.Errorf("invalid CV-sAPVSS component dispersal")
	}
	if err := cvWriteBytes(wire, dispersal.nonce); err != nil {
		return err
	}
	if err := cvWriteUint32(wire, dispersal.dataShards); err != nil {
		return err
	}
	if err := cvWriteUint32(wire, dispersal.shardBytes); err != nil {
		return err
	}
	if err := cvWriteBytes(wire, dispersal.payloadDigest); err != nil {
		return err
	}
	if err := cvWriteBytes(wire, dispersal.semanticCommitment); err != nil {
		return err
	}
	if err := cvWriteBytes(wire, dispersal.root); err != nil {
		return err
	}
	for _, fingerprint := range dispersal.dataFingerprints {
		if err := cvWriteBytes(wire, fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func cvReadComponentDispersal(r *cvWireReader) (*cvComponentDispersal, error) {
	nonce, err := r.bytes(32)
	if err != nil || len(nonce) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component dispersal nonce")
	}
	dataShards, err := r.uint32()
	if err != nil || dataShards <= 0 || dataShards > 1<<16 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component data shard count")
	}
	shardBytes, err := r.uint32()
	if err != nil || shardBytes <= 0 || shardBytes > cvMaxLeafWireBytes+8 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard length")
	}
	payloadDigest, err := r.bytes(32)
	if err != nil || len(payloadDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component payload digest")
	}
	semanticCommitment, err := r.bytes(bnfr.Bytes)
	if err != nil || !cvValidLeafSemanticCommitment(semanticCommitment) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component semantic commitment")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard root")
	}
	dataFingerprints := make([][]byte, dataShards)
	for i := range dataFingerprints {
		dataFingerprints[i], err = r.bytes(cvComponentCodewordChecks)
		if err != nil || len(dataFingerprints[i]) != cvComponentCodewordChecks {
			return nil, fmt.Errorf("invalid CV-sAPVSS component codeword fingerprint")
		}
	}
	return &cvComponentDispersal{
		nonce: nonce, dataShards: dataShards, shardBytes: shardBytes,
		payloadDigest: payloadDigest, semanticCommitment: semanticCommitment,
		root: root, dataFingerprints: dataFingerprints,
	}, nil
}

func cvDisperseComponent(leafWire []byte, totalShards, dataShards int) (*cvComponentDispersal, []cvComponentShard, error) {
	if len(leafWire) == 0 || len(leafWire) > cvMaxLeafWireBytes || totalShards <= 0 || dataShards <= 0 || dataShards > totalShards {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS component dispersal parameters")
	}
	packed := make([]byte, 8+len(leafWire))
	binary.BigEndian.PutUint64(packed[:8], uint64(len(leafWire)))
	copy(packed[8:], leafWire)
	shards, err := cvErasureEncode(packed, dataShards, totalShards)
	if err != nil {
		return nil, nil, err
	}
	nonce := hashBytes([]byte(cvComponentShardDomain), cvComponentLeafPayloadDigest(leafWire))
	root, branches := cvBuildComponentMerkle(nonce, shards)
	dataFingerprints, err := cvBuildComponentCodewordProof(root, shards, dataShards)
	if err != nil {
		return nil, nil, err
	}
	dispersal := &cvComponentDispersal{
		nonce: nonce, dataShards: dataShards, shardBytes: len(shards[0]),
		payloadDigest: hashBytes([]byte(cvComponentPayloadDomain), leafWire), root: root,
		dataFingerprints: dataFingerprints,
	}
	dispersal.semanticCommitment, err = cvLeafSemanticCommitment(leafWire)
	if err != nil {
		return nil, nil, err
	}
	encoded := make([]cvComponentShard, len(shards))
	for i := range shards {
		encoded[i] = cvComponentShard{index: i, payload: append([]byte(nil), shards[i]...), siblings: branches[i]}
	}
	return dispersal, encoded, nil
}

func cvVerifyComponentShard(dispersal *cvComponentDispersal, totalShards int, shard *cvComponentShard) error {
	if !cvValidComponentDispersalForRoster(dispersal, totalShards) || shard == nil || shard.index < 0 || shard.index >= totalShards || len(shard.payload) == 0 {
		return fmt.Errorf("invalid CV-sAPVSS component shard")
	}
	digest := cvComponentShardHash(dispersal.nonce, shard.index, shard.payload)
	index := shard.index
	for _, sibling := range shard.siblings {
		if len(sibling) != 32 {
			return fmt.Errorf("invalid CV-sAPVSS component shard branch")
		}
		if index%2 == 0 {
			digest = hashBytes([]byte(cvComponentShardNodeDomain), digest, sibling)
		} else {
			digest = hashBytes([]byte(cvComponentShardNodeDomain), sibling, digest)
		}
		index /= 2
	}
	if !bytes.Equal(digest, dispersal.root) {
		return fmt.Errorf("CV-sAPVSS component shard root mismatch")
	}
	return cvVerifyComponentCodewordShard(dispersal, totalShards, shard)
}

func cvRecoverComponentWire(dispersal *cvComponentDispersal, totalShards int, available map[int]cvComponentShard) ([]byte, error) {
	if !cvValidComponentDispersalForRoster(dispersal, totalShards) || len(available) < dispersal.dataShards {
		return nil, fmt.Errorf("insufficient CV-sAPVSS component shards")
	}
	shards := make([][]byte, totalShards)
	for index, shard := range available {
		if index != shard.index || cvVerifyComponentShard(dispersal, totalShards, &shard) != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS component shard during recovery")
		}
		shards[index] = append([]byte(nil), shard.payload...)
	}
	packed, err := cvErasureDecode(shards, dispersal.dataShards)
	if err != nil || len(packed) < 8 {
		return nil, fmt.Errorf("recover CV-sAPVSS component: %w", err)
	}
	length := binary.BigEndian.Uint64(packed[:8])
	if length > uint64(len(packed)-8) || length > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid recovered CV-sAPVSS component length")
	}
	leafWire := append([]byte(nil), packed[8:8+int(length)]...)
	if !bytes.Equal(hashBytes([]byte(cvComponentPayloadDomain), leafWire), dispersal.payloadDigest) {
		return nil, fmt.Errorf("recovered CV-sAPVSS component payload digest mismatch")
	}
	semanticCommitment, err := cvLeafSemanticCommitment(leafWire)
	if err != nil || !bytes.Equal(semanticCommitment, dispersal.semanticCommitment) {
		return nil, fmt.Errorf("recovered CV-sAPVSS component semantic commitment mismatch")
	}
	return leafWire, nil
}

func cvComponentShardHash(nonce []byte, index int, payload []byte) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(index))
	return hashBytes([]byte(cvComponentShardDomain), nonce, encoded[:], payload)
}

func cvBuildComponentMerkle(nonce []byte, shards [][]byte) ([]byte, [][][]byte) {
	levels := [][][]byte{make([][]byte, len(shards))}
	for i := range shards {
		levels[0][i] = cvComponentShardHash(nonce, i, shards[i])
	}
	for len(levels[len(levels)-1]) > 1 {
		level := levels[len(levels)-1]
		padded := level
		if len(level)%2 == 1 {
			padded = append(append([][]byte(nil), level...), level[len(level)-1])
		}
		next := make([][]byte, 0, len(padded)/2)
		for i := 0; i < len(padded); i += 2 {
			next = append(next, hashBytes([]byte(cvComponentShardNodeDomain), padded[i], padded[i+1]))
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

func cvComponentShardArtifactCanonicalBytes(artifact *cvComponentShardArtifact) ([]byte, error) {
	if artifact == nil || artifact.dealer < 0 || len(artifact.leafDigest) != 32 ||
		!cvValidComponentDispersal(&artifact.dispersal) || artifact.shard.index < 0 || len(artifact.shard.payload) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard artifact")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentShardArtifactDomain))
	cvWriteUint64(&wire, uint64(artifact.dealer))
	_ = cvWriteBytes(&wire, artifact.leafDigest)
	if err := cvWriteComponentDispersal(&wire, &artifact.dispersal); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, artifact.shard.index); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, artifact.shard.payload); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(artifact.shard.siblings)); err != nil {
		return nil, err
	}
	for _, sibling := range artifact.shard.siblings {
		if err := cvWriteBytes(&wire, sibling); err != nil {
			return nil, err
		}
	}
	return wire.Bytes(), nil
}

func cvDecodeComponentShardArtifact(wire []byte, expectedDealer, totalShards int) (*cvComponentShardArtifact, error) {
	if expectedDealer < 0 || totalShards <= 0 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS component shard")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentShardArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentShardArtifactDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard artifact domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) || int(dealer) != expectedDealer {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard dealer")
	}
	leafDigest, err := r.bytes(32)
	if err != nil || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard digest")
	}
	dispersal, err := cvReadComponentDispersal(r)
	if err != nil || !cvValidComponentDispersalForRoster(dispersal, totalShards) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard dispersal")
	}
	index, err := r.uint32()
	if err != nil || index < 0 || index >= totalShards {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard index")
	}
	payload, err := r.bytes(cvMaxLeafWireBytes + 8)
	if err != nil || len(payload) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard payload")
	}
	count, err := r.uint32()
	if err != nil || count < 0 || count > 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component shard branch count")
	}
	siblings := make([][]byte, count)
	for i := range siblings {
		siblings[i], err = r.bytes(32)
		if err != nil || len(siblings[i]) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS component shard branch")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS component shard bytes")
	}
	artifact := &cvComponentShardArtifact{dealer: int(dealer), leafDigest: leafDigest, dispersal: *dispersal, shard: cvComponentShard{index: index, payload: payload, siblings: siblings}}
	if err := cvVerifyComponentShard(&artifact.dispersal, totalShards, &artifact.shard); err != nil {
		return nil, err
	}
	canonical, err := cvComponentShardArtifactCanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component shard artifact")
	}
	return artifact, nil
}

func cvValidateComponentDescriptorShape(descriptor *cvComponentDescriptor) error {
	if descriptor == nil || descriptor.dealer < 0 || len(descriptor.leafDigest) != 32 ||
		!cvValidComponentDispersal(&descriptor.dispersal) ||
		len(descriptor.certificate) == 0 || len(descriptor.certificate) > cvMaxComponentSignatureBytes {
		return fmt.Errorf("invalid CV-sAPVSS component descriptor")
	}
	return nil
}

// cvValidateComponentDescriptor validates only the compact recovered
// threshold certificate; individual signature shares never leave the collector.
func cvValidateComponentDescriptor(cfg Config, descriptor *cvComponentDescriptor) error {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return err
	}
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil || c.runtime.lockSigner == nil {
		return fmt.Errorf("CV-sAPVSS component lock signer is unavailable")
	}
	if err := cvValidateComponentDescriptorShape(descriptor); err != nil {
		return err
	}
	oldSet := nodeSet(sortedUnique(c.OldCommittee))
	if _, ok := oldSet[descriptor.dealer]; !ok {
		return fmt.Errorf("CV-sAPVSS component dealer is outside old roster")
	}
	if !cvValidComponentDispersalForRoster(&descriptor.dispersal, len(c.OldCommittee)) ||
		descriptor.dispersal.dataShards != len(c.OldCommittee)-2*c.FOld {
		return fmt.Errorf("invalid CV-sAPVSS component recovery threshold")
	}
	statement, err := cvComponentStatementDigest(descriptor.dealer, descriptor.leafDigest, &descriptor.dispersal)
	if err != nil {
		return err
	}
	if !c.runtime.lockSigner.VerifyRecovered(
		cvComponentLockSignatureDomain, statement, descriptor.certificate,
	) {
		return fmt.Errorf("invalid CV-sAPVSS component lock certificate")
	}
	return nil
}
