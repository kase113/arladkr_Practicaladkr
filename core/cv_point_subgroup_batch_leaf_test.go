package core

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// TestCVLeafWideSubgroupBatchRejectsPlantedOutsider builds one real leaf,
// replaces a coefficient commitment with an on-curve point outside the
// prime-order subgroup, re-encodes the wire, and proves the leaf-wide
// deferred subgroup batch rejects the decode before dealer-signature or
// APVSS checks could accept any structure.
func TestCVLeafWideSubgroupBatchRejectsPlantedOutsider(t *testing.T) {
	const (
		n = 7
		f = 2
	)
	oldRoster := make([]int, n)
	newRoster := make([]int, n)
	for i := range oldRoster {
		oldRoster[i] = i
		newRoster[i] = n + i
	}
	cfg := Config{
		SID: "cv-v2-leaf-subgroup-adversarial", Epoch: 1,
		OldCommittee: oldRoster, NewCommittee: newRoster,
		OldFaults: f, NewFaults: f,
		CVProposerSampleSize: 3, CVValidatorSampleSize: 3,
	}
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keyRoot := t.TempDir()
	receiverPublic := filepath.Join(keyRoot, "receiver-public")
	receiverSecret := filepath.Join(keyRoot, "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), newRoster); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryV2(
		receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), newRoster, newRoster,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatorPublic := filepath.Join(keyRoot, "validator-public")
	validatorSecret := filepath.Join(keyRoot, "validator-secret")
	if err := cvGenerateValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), oldRoster); err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryV2(
		validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), oldRoster, oldRoster,
	)
	if err != nil {
		t.Fatal(err)
	}
	leafContext := &cvLeafContextV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch),
		OldRoster: append([]int(nil), oldRoster...), NewRoster: append([]int(nil), newRoster...),
		ReceiverRegistryDigest: append([]byte(nil), receivers.registryDigest...),
		SharingDegree:          params.newShareDegree,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	leaf, err := cvBuildReferenceAllACKLeafV2(oldRoster[0], leafContext, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeLeafV2Sidechannel(payload, nil, leafContext, receivers, validators); err != nil {
		t.Fatalf("clean leaf failed to decode: %v", err)
	}

	outsider := cvRandomCurvePointOutsideSubgroup(t)
	leaf.CoefficientCommitments[0] = outsider
	unsigned, err := cvLeafV2UnsignedCanonicalBytesAfterValidation(leaf, receivers)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLeafWireDomainV2))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, bytes.Repeat([]byte{0xA5}, 48))
	_, err = cvDecodeLeafV2Sidechannel(wire.Bytes(), nil, leafContext, receivers, validators)
	if err == nil {
		t.Fatal("leaf decode accepted a planted non-subgroup commitment")
	}
	if !strings.Contains(err.Error(), "leaf point") || !strings.Contains(err.Error(), "subgroup") {
		t.Fatalf("leaf decode failed for an unexpected reason before the subgroup gate: %v", err)
	}
}

// TestCVDecodeSidechannelSubgroupCollector exercises the collector mechanics:
// section readers hand their deferred points to the shared sidechannel and a
// single leaf-level batch decides acceptance.
func TestCVDecodeSidechannelSubgroupCollector(t *testing.T) {
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte{}
	for _, point := range []bls12381.G1Affine{genG1, h} {
		encoded := point.Bytes()
		valid = append(valid, encoded[:]...)
	}
	outsider := cvRandomCurvePointOutsideSubgroup(t)

	side := &cvDecodeSidechannelV2{collectSubgroup: true}
	first := newCVWireReaderSide(valid, side)
	for range 2 {
		if _, err := first.pointDeferred(); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.assertDecodedSubgroup(); err != nil {
		t.Fatal(err)
	}
	if len(first.deferredPoints) != 0 || len(side.deferredBatch) != 2 {
		t.Fatal("section reader did not hand its points to the leaf collector")
	}

	second := newCVWireReaderSide(valid, side)
	for range 2 {
		if _, err := second.pointDeferred(); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.assertDecodedSubgroup(); err != nil {
		t.Fatal(err)
	}
	if len(side.deferredBatch) != 4 {
		t.Fatal("collector did not accumulate across section readers")
	}
	if err := side.finishDeferredSubgroupBatch(); err != nil {
		t.Fatalf("valid collected batch rejected: %v", err)
	}
	if len(side.deferredBatch) != 0 {
		t.Fatal("collector not reset after a finished batch")
	}

	bad := append([]byte(nil), valid...)
	encoded := outsider.Bytes()
	bad = append(bad, encoded[:]...)
	third := newCVWireReaderSide(bad, side)
	for range 3 {
		if _, err := third.pointDeferred(); err != nil {
			t.Fatal(err)
		}
	}
	if err := third.assertDecodedSubgroup(); err != nil {
		t.Fatal(err)
	}
	if err := side.finishDeferredSubgroupBatch(); err == nil {
		t.Fatal("leaf-level batch accepted an accumulated non-subgroup point")
	}
}
