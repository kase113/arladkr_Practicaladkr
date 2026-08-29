package core

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVFallbackLinkV2BindsCommitmentsCiphertextsAndEvaluation(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, witness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, local, err := cvProveFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey},
		[]*cvDealerReceiverWitnessV2{witness},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(local.Blindings) != len(proof.DigitCommitments) {
		t.Fatal("fallback range witness does not match digit commitments")
	}
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err != nil {
		t.Fatal(err)
	}
	wire, err := cvFallbackLinkProofV2CanonicalBytes(proof, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeFallbackLinkProofV2(wire, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, decoded,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeFallbackLinkProofV2(append(append([]byte(nil), wire...), 0), context, 1); err == nil {
		t.Fatal("accepted fallback-link proof with trailing bytes")
	}

	badCommitment := *proof
	badCommitment.DigitCommitments = append([]bls12381.G1Affine(nil), proof.DigitCommitments...)
	badCommitment.DigitCommitments[0].Add(&badCommitment.DigitCommitments[0], &genG1)
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, &badCommitment,
	); err == nil {
		t.Fatal("accepted mutated fallback digit commitment")
	}
	badResponse := *proof
	badResponse.DigitResponses = append([]fr.Element(nil), proof.DigitResponses...)
	var one fr.Element
	one.SetOne()
	badResponse.DigitResponses[0].Add(&badResponse.DigitResponses[0], &one)
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, &badResponse,
	); err == nil {
		t.Fatal("accepted mutated fallback digit response")
	}
	badOffer := *cvCloneReceiverLaneOfferV2(offer)
	badOffer.ScalarChunks[0].c.Add(&badOffer.ScalarChunks[0].c, &genG1)
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{&badOffer}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after ciphertext mutation")
	}
	badBlinding := *cvCloneReceiverLaneOfferV2(offer)
	badBlinding.Blinding.c.Add(&badBlinding.Blinding.c, &genG1)
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{&badBlinding}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after blinding ciphertext mutation")
	}
	badEvaluation := *cvCloneReceiverLaneOfferV2(offer)
	badEvaluation.Evaluation.Add(&badEvaluation.Evaluation, &genG1)
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{&badEvaluation}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after evaluation mutation")
	}
	if err := cvVerifyFallbackLinkV2(
		context, 99, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("accepted fallback-link proof for a dealer outside the old roster")
	}
}

func TestCVFallbackLinkV2DoesNotMasqueradeAsRangeProof(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, witness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	base, _, _, err := cvProfile(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	oldDigit := witness.ScalarDigits[0]
	witness.ScalarDigits[0] = base
	var outOfRangePoint bls12381.G1Affine
	outOfRangePoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(base))
	offer.ScalarChunks[0], err = cvEncryptPoint(&publicKey, &outOfRangePoint, witness.ScalarCoins[0])
	if err != nil {
		t.Fatal(err)
	}
	delta := new(big.Int).SetUint64(base - oldDigit)
	var deltaPoint bls12381.G1Affine
	deltaPoint.ScalarMultiplication(&genG1, delta)
	offer.Evaluation.Add(&offer.Evaluation, &deltaPoint)
	proof, _, err := cvProveFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey},
		[]*cvDealerReceiverWitnessV2{witness},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackLinkV2(
		context, dealer, []*cvReceiverLaneOfferV2{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err != nil {
		t.Fatalf("link proof incorrectly enforced the missing range relation: %v", err)
	}
}
