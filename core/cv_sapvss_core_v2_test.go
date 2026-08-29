package core

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvCoreProofV2Fixture(t testing.TB) (*cvLeafContextV2, []fr.Element, []fr.Element) {
	t.Helper()
	cfg := cvV2ParamsTestConfig()
	context := &cvLeafContextV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch),
		OldRoster: append([]int(nil), cfg.OldCommittee...), NewRoster: append([]int(nil), cfg.NewCommittee...),
		ReceiverRegistryDigest: hashBytes([]byte("V2 receiver registry")),
		SharingDegree:          len(cfg.NewCommittee) - cfg.NewFaults - 1,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: cfg.OldFaults + 1},
	}
	count := context.SharingDegree + 1
	scalars := make([]fr.Element, count)
	blindings := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		if _, err := scalars[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
		if _, err := blindings[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
	}
	return context, scalars, blindings
}

func TestCVCoreProofV2PedersenKnowledgeAndCodec(t *testing.T) {
	context, scalars, blindings := cvCoreProofV2Fixture(t)
	dealer := context.OldRoster[0]
	commitments, proof, err := cvProveCoreV2(context, dealer, scalars, blindings)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyCoreV2(context, dealer, commitments, proof); err != nil {
		t.Fatalf("verify V2 core proof: %v", err)
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		t.Fatal(err)
	}
	decodedContext, err := cvDecodeLeafContextV2(contextWire)
	if err != nil {
		t.Fatal(err)
	}
	decodedWire, err := cvLeafContextV2CanonicalBytes(decodedContext)
	if err != nil || !bytes.Equal(decodedWire, contextWire) {
		t.Fatalf("V2 context round trip: %v", err)
	}
	proofWire, err := cvCoreProofV2CanonicalBytes(proof, len(commitments))
	if err != nil {
		t.Fatal(err)
	}
	decodedProof, err := cvDecodeCoreProofV2(proofWire, len(commitments))
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyCoreV2(decodedContext, dealer, commitments, decodedProof); err != nil {
		t.Fatalf("verify decoded V2 core proof: %v", err)
	}
	if _, err := cvDecodeLeafContextV2(append(append([]byte(nil), contextWire...), 0)); err == nil {
		t.Fatal("accepted V2 leaf context with trailing bytes")
	}
	if _, err := cvDecodeCoreProofV2(append(append([]byte(nil), proofWire...), 0), len(commitments)); err == nil {
		t.Fatal("accepted V2 core proof with trailing bytes")
	}
}

func TestCVCoreProofV2RejectsStatementAndWitnessMutations(t *testing.T) {
	context, scalars, blindings := cvCoreProofV2Fixture(t)
	dealer := context.OldRoster[0]
	commitments, proof, err := cvProveCoreV2(context, dealer, scalars, blindings)
	if err != nil {
		t.Fatal(err)
	}
	wrongContext := *context
	wrongContext.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	wrongContext.ReceiverRegistryDigest[0] ^= 1
	if err := cvVerifyCoreV2(&wrongContext, dealer, commitments, proof); err == nil {
		t.Fatal("accepted V2 core proof under another receiver registry")
	}
	if err := cvVerifyCoreV2(context, dealer+1, commitments, proof); err == nil {
		t.Fatal("accepted V2 core proof under another dealer")
	}
	mutatedCommitments := append([]bls12381.G1Affine(nil), commitments...)
	mutatedCommitments[0].Add(&mutatedCommitments[0], &genG1)
	if err := cvVerifyCoreV2(context, dealer, mutatedCommitments, proof); err == nil {
		t.Fatal("accepted mutated V2 coefficient commitment")
	}
	mutatedProof := *proof
	mutatedProof.ScalarResponses = append([]fr.Element(nil), proof.ScalarResponses...)
	one := fr.One()
	mutatedProof.ScalarResponses[0].Add(&mutatedProof.ScalarResponses[0], &one)
	if err := cvVerifyCoreV2(context, dealer, commitments, &mutatedProof); err == nil {
		t.Fatal("accepted mutated V2 core proof response")
	}
}

func TestCVLeafContextV2RejectsNonCanonicalOrUnsafeParameters(t *testing.T) {
	context, _, _ := cvCoreProofV2Fixture(t)
	unsorted := *context
	unsorted.OldRoster = append([]int(nil), context.OldRoster...)
	unsorted.OldRoster[0], unsorted.OldRoster[1] = unsorted.OldRoster[1], unsorted.OldRoster[0]
	if _, err := cvLeafContextV2CanonicalBytes(&unsorted); err == nil {
		t.Fatal("accepted non-canonical V2 old roster")
	}
	badDegree := *context
	badDegree.SharingDegree = len(context.NewRoster)
	if _, err := cvLeafContextV2CanonicalBytes(&badDegree); err == nil {
		t.Fatal("accepted V2 sharing degree outside receiver roster")
	}
	badProfile := *context
	badProfile.Profile.chunkBits = 0
	if _, err := cvLeafContextV2CanonicalBytes(&badProfile); err == nil {
		t.Fatal("accepted invalid V2 chunk profile")
	}
}
