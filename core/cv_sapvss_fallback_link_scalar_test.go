package core

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVFallbackLinkScalarBindsCommitmentsCiphertextsAndEvaluation(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesScalarFixture(t)
	offer, witness, err := cvEncryptReceiverLanesScalar(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, local, err := cvProveFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey},
		[]*cvDealerReceiverWitnessScalar{witness},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(local.Blindings) != len(proof.DigitCommitments) {
		t.Fatal("fallback range witness does not match digit commitments")
	}
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err != nil {
		t.Fatal(err)
	}
	wire, err := cvFallbackLinkProofScalarCanonicalBytes(proof, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeFallbackLinkProofScalar(wire, context, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, decoded,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeFallbackLinkProofScalar(append(append([]byte(nil), wire...), 0), context, 1); err == nil {
		t.Fatal("accepted fallback-link proof with trailing bytes")
	}

	badCommitment := *proof
	badCommitment.DigitCommitments = append([]bls12381.G1Affine(nil), proof.DigitCommitments...)
	badCommitment.DigitCommitments[0].Add(&badCommitment.DigitCommitments[0], &genG1)
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, &badCommitment,
	); err == nil {
		t.Fatal("accepted mutated fallback digit commitment")
	}
	badResponse := *proof
	badResponse.DigitResponses = append([]fr.Element(nil), proof.DigitResponses...)
	var one fr.Element
	one.SetOne()
	badResponse.DigitResponses[0].Add(&badResponse.DigitResponses[0], &one)
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, &badResponse,
	); err == nil {
		t.Fatal("accepted mutated fallback digit response")
	}
	badOffer := *cvCloneReceiverLaneOfferScalar(offer)
	badOffer.ScalarChunks[0].c.Add(&badOffer.ScalarChunks[0].c, &genG1)
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{&badOffer}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after ciphertext mutation")
	}
	badBlinding := *cvCloneReceiverLaneOfferScalar(offer)
	badBlinding.Blinding.c.Add(&badBlinding.Blinding.c, &genG1)
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{&badBlinding}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after blinding ciphertext mutation")
	}
	badEvaluation := *cvCloneReceiverLaneOfferScalar(offer)
	badEvaluation.Evaluation.Add(&badEvaluation.Evaluation, &genG1)
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{&badEvaluation}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("replayed fallback-link proof after evaluation mutation")
	}
	if err := cvVerifyFallbackLinkScalar(
		context, 99, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err == nil {
		t.Fatal("accepted fallback-link proof for a dealer outside the old roster")
	}
}

func TestCVFallbackLinkScalarDoesNotMasqueradeAsRangeProof(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesScalarFixture(t)
	offer, witness, err := cvEncryptReceiverLanesScalar(
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
	proof, _, err := cvProveFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey},
		[]*cvDealerReceiverWitnessScalar{witness},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyFallbackLinkScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{offer}, []bls12381.G1Affine{publicKey}, proof,
	); err != nil {
		t.Fatalf("link proof incorrectly enforced the missing range relation: %v", err)
	}
}
