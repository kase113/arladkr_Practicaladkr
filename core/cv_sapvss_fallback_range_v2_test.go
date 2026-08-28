package core

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVFallbackRangeV2UsesExactLinkCommitmentsAndStrictCodec(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, dealerWitness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	offers := []*cvReceiverLaneOfferV2{offer}
	publicKeys := []bls12381.G1Affine{publicKey}
	witnesses := []*cvDealerReceiverWitnessV2{dealerWitness}
	linkProof, linkWitness, err := cvProveFallbackLinkV2(context, dealer, offers, publicKeys, witnesses)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	for chunk := 0; chunk < chunks; chunk++ {
		position := cvFallbackLinkPositionV2(0, chunk, chunks)
		want, err := apvssCompactRangeCommitment(dealerWitness.ScalarDigits[chunk], linkWitness.Blindings[position])
		if err != nil || !want.Equal(&linkProof.DigitCommitments[position]) {
			t.Fatalf("range/link commitment mismatch at %d: %v", position, err)
		}
	}
	rangeProof, err := cvProveFallbackRangeV2(
		context, dealer, offers, publicKeys, witnesses, linkProof, linkWitness,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackRangeV2(context, dealer, offers, publicKeys, linkProof, rangeProof); err != nil {
		t.Fatal(err)
	}
	if rangeProof.proof.valueCount != chunks {
		t.Fatalf("fallback range value count = %d, want scalar chunks %d", rangeProof.proof.valueCount, chunks)
	}
	if err := cvRequireV2FallbackBackend(); err != nil {
		t.Fatalf("V2 fallback backend gate remained closed: %v", err)
	}
	wire, err := cvFallbackRangeProofV2CanonicalBytes(rangeProof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeFallbackRangeProofV2(wire, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackRangeV2(context, dealer, offers, publicKeys, linkProof, decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeFallbackRangeProofV2(append(append([]byte(nil), wire...), 0), context, 1); err == nil {
		t.Fatal("accepted CV V2 fallback-range proof with trailing bytes")
	}

	badProof := *rangeProof
	badProof.proof = apvssCloneCompactRangeProofForTest(rangeProof.proof)
	one := fr.One()
	badProof.proof.tHat.Add(&badProof.proof.tHat, &one)
	if err := cvVerifyFallbackRangeV2(context, dealer, offers, publicKeys, linkProof, &badProof); err == nil {
		t.Fatal("accepted mutated CV V2 fallback-range response")
	}
	badBackend := *rangeProof
	badBackend.backend = "legacy-compact-range"
	if err := cvVerifyFallbackRangeV2(context, dealer, offers, publicKeys, linkProof, &badBackend); err == nil {
		t.Fatal("accepted CV V2 fallback-range backend downgrade")
	}
	badLink := *linkProof
	badLink.DigitCommitments = append([]bls12381.G1Affine(nil), linkProof.DigitCommitments...)
	badLink.DigitCommitments[0].Add(&badLink.DigitCommitments[0], &genG1)
	if err := cvVerifyFallbackRangeV2(context, dealer, offers, publicKeys, &badLink, rangeProof); err == nil {
		t.Fatal("accepted range proof for another link commitment")
	}

	base, _, _, err := cvProfile(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	dealerWitness.ScalarDigits[0] = base
	if _, err := cvProveFallbackRangeV2(
		context, dealer, offers, publicKeys, witnesses, linkProof, linkWitness,
	); err == nil {
		t.Fatal("proved CV V2 fallback range for digit B")
	}
}
