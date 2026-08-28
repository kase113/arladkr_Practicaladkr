package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvReceiverLanesV2Fixture(
	t *testing.T,
) (*cvLeafContextV2, int, int, int, fr.Element, bls12381.G1Affine, fr.Element, fr.Element) {
	t.Helper()
	context, coefficients, blindings := cvCoreProofV2Fixture(t)
	dealer := context.OldRoster[0]
	receiverID := context.NewRoster[1]
	receiverIndex := 2
	var receiverSecret fr.Element
	if _, err := receiverSecret.SetRandom(); err != nil {
		t.Fatal(err)
	}
	receiverPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		t.Fatal(err)
	}
	return context, dealer, receiverID, receiverIndex, receiverSecret, receiverPublic, coefficients[0], blindings[0]
}

func TestCVReceiverLanesV2UseScalarChunksAndGroupBlinding(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, witness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyOwnershipV2(context, dealer, offer, &publicKey); err != nil {
		t.Fatalf("verify V2 ownership proof: %v", err)
	}
	recoveredScalar, recoveredBlinding, err := cvVerifyAndDecryptReceiverLanesV2(
		context, dealer, offer, &publicKey, secret,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	wantBlinding := cvPointTimes(&h, &blinding)
	if !recoveredScalar.Equal(&scalar) || !recoveredBlinding.Equal(&wantBlinding) {
		t.Fatal("scalar/group decryption did not recover the Pedersen opening")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(offer.ScalarChunks) != chunks || len(witness.ScalarCoins) != chunks ||
		!cvValidCiphertext(&offer.Blinding) {
		t.Fatal("V2 offer is not exactly scalar chunks plus one blinding ciphertext")
	}
	seenCoins := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{})
	for chunk := range offer.ScalarChunks {
		key := cvPointKey(&offer.ScalarChunks[chunk].r)
		if _, duplicate := seenCoins[key]; duplicate {
			t.Fatal("V2 scalar chunks reused an encryption coin")
		}
		seenCoins[key] = struct{}{}
	}
	if _, duplicate := seenCoins[cvPointKey(&offer.Blinding.r)]; duplicate {
		t.Fatal("V2 blinding ciphertext reused a scalar encryption coin")
	}
}

func TestCVReceiverLanesV2DecodedPathStillVerifiesOwnershipEquations(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealer, offer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeReceiverLaneOfferBeforeVerificationV2(
		wire, context, dealer, receiverID, receiverIndex, &publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, decoded, &publicKey, secret,
	); err != nil {
		t.Fatalf("decoded receiver lane verification failed: %v", err)
	}

	badProof := *decoded
	badProof.Ownership = cvCloneOwnershipProofV2(&decoded.Ownership)
	one := fr.One()
	badProof.Ownership.BlindingShareResponse.Add(&badProof.Ownership.BlindingShareResponse, &one)
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, &badProof, &publicKey, secret,
	); err == nil {
		t.Fatal("decoded receiver path accepted a mutated ownership response")
	}

	badCiphertext := *decoded
	badCiphertext.ScalarChunks = append([]cvElGamalCiphertext(nil), decoded.ScalarChunks...)
	badCiphertext.ScalarChunks[0].c.Add(&badCiphertext.ScalarChunks[0].c, &genG1)
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, &badCiphertext, &publicKey, secret,
	); err == nil {
		t.Fatal("decoded receiver path accepted a ciphertext mutation")
	}
}

func TestCVOwnershipProofV2RejectsCiphertextEvaluationAndBindingMutations(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}

	badCiphertext := *offer
	badCiphertext.ScalarChunks = append([]cvElGamalCiphertext(nil), offer.ScalarChunks...)
	badCiphertext.ScalarChunks[0].c.Add(&badCiphertext.ScalarChunks[0].c, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badCiphertext, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after ciphertext mutation")
	}
	badBlinding := *offer
	badBlinding.Blinding.c.Add(&badBlinding.Blinding.c, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badBlinding, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after blinding ciphertext mutation")
	}

	badEvaluation := *offer
	badEvaluation.Evaluation.Add(&badEvaluation.Evaluation, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badEvaluation, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after evaluation mutation")
	}
	if err := cvVerifyOwnershipV2(context, dealer+1, offer, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another dealer")
	}
	badReceiver := *offer
	badReceiver.ReceiverID = context.NewRoster[0]
	if err := cvVerifyOwnershipV2(context, dealer, &badReceiver, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under a mismatched receiver binding")
	}
	badIndex := *offer
	badIndex.ReceiverIndex = 1
	if err := cvVerifyOwnershipV2(context, dealer, &badIndex, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another receiver index")
	}
	badContext := *context
	badContext.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	badContext.ReceiverRegistryDigest[0] ^= 1
	if err := cvVerifyOwnershipV2(&badContext, dealer, offer, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another receiver registry")
	}
	badProof := *offer
	badProof.Ownership = cvCloneOwnershipProofV2(&offer.Ownership)
	var one fr.Element
	one.SetOne()
	badProof.Ownership.BlindingShareResponse.Add(&badProof.Ownership.BlindingShareResponse, &one)
	if err := cvVerifyOwnershipV2(context, dealer, &badProof, &publicKey); err == nil {
		t.Fatal("accepted mutated blinding-share ownership response")
	}

	var wrongSecret fr.Element
	if _, err := wrongSecret.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesV2(context, dealer, offer, &publicKey, wrongSecret); err == nil {
		t.Fatal("decrypted V2 lanes with a secret outside the receiver registry")
	}
}

func TestCVReceiverLanesV2RejectOutOfRangeDigitAfterValidOwnershipProof(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
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
	proof, err := cvProveOwnershipV2(context, dealer, offer, &publicKey, witness)
	if err != nil {
		t.Fatal(err)
	}
	offer.Ownership = *proof
	if err := cvVerifyOwnershipV2(context, dealer, offer, &publicKey); err != nil {
		t.Fatalf("ownership proof should not claim a range relation: %v", err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesV2(context, dealer, offer, &publicKey, secret); err == nil {
		t.Fatal("accepted out-of-range V2 digit after valid ownership proof")
	}
}

func TestCVReceiverLanesV2BatchedOfferMatchesScalarReference(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	randomness := &cvReceiverLaneRandomnessV2{
		scalarCoins: make([]fr.Element, chunks), coinNonces: make([]fr.Element, chunks),
		digitNonces: make([]fr.Element, chunks),
	}
	for chunk := 0; chunk < chunks; chunk++ {
		randomness.scalarCoins[chunk].SetUint64(uint64(chunk + 1))
		randomness.coinNonces[chunk].SetUint64(uint64(3*chunks + chunk))
		randomness.digitNonces[chunk].SetUint64(uint64(5*chunks + chunk))
	}
	randomness.blindingCoin.SetUint64(101)
	randomness.blindingCoinNonce.SetUint64(102)
	randomness.blindingShareNonce.SetUint64(103)
	offer, witness, err := cvComputeReceiverLaneOfferV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding, randomness,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	scalarMult := func(point *bls12381.G1Affine, value fr.Element) bls12381.G1Affine {
		var result bls12381.G1Affine
		result.ScalarMultiplication(point, value.BigInt(new(big.Int)))
		return result
	}
	for chunk := range offer.ScalarChunks {
		wantR := scalarMult(&genG1, randomness.scalarCoins[chunk])
		if !offer.ScalarChunks[chunk].r.Equal(&wantR) {
			t.Fatalf("chunk %d r mismatch", chunk)
		}
		digit := witness.ScalarDigits[chunk]
		wantDigit := scalarMult(&genG1, func() fr.Element { var d fr.Element; d.SetUint64(digit); return d }())
		wantShared := scalarMult(&publicKey, randomness.scalarCoins[chunk])
		wantC := cvPointSum(&wantShared, &wantDigit)
		if !offer.ScalarChunks[chunk].c.Equal(&wantC) {
			t.Fatalf("chunk %d c mismatch", chunk)
		}
		wantCoin := scalarMult(&genG1, randomness.coinNonces[chunk])
		if !offer.Ownership.ScalarCoinCommitments[chunk].Equal(&wantCoin) {
			t.Fatalf("chunk %d coin commitment mismatch", chunk)
		}
		wantDigitNonce := scalarMult(&genG1, randomness.digitNonces[chunk])
		wantCipher := cvPointSum(&wantDigitNonce, pointPtr(scalarMult(&publicKey, randomness.coinNonces[chunk])))
		if !offer.Ownership.ScalarCipherCommitments[chunk].Equal(&wantCipher) {
			t.Fatalf("chunk %d cipher commitment mismatch", chunk)
		}
	}
	wantBlindingR := scalarMult(&genG1, randomness.blindingCoin)
	if !offer.Blinding.r.Equal(&wantBlindingR) {
		t.Fatal("blinding r mismatch")
	}
	wantBlindingC := cvPointSum(
		pointPtr(scalarMult(&publicKey, randomness.blindingCoin)),
		pointPtr(cvPointTimes(&h, &blinding)),
	)
	if !offer.Blinding.c.Equal(&wantBlindingC) {
		t.Fatal("blinding c mismatch")
	}
	wantEvaluation := cvPointSum(pointPtr(scalarMult(&genG1, scalar)), pointPtr(cvPointTimes(&h, &blinding)))
	if !offer.Evaluation.Equal(&wantEvaluation) {
		t.Fatal("evaluation mismatch")
	}
	wantBlindingCoinCommitment := scalarMult(&genG1, randomness.blindingCoinNonce)
	if !offer.Ownership.BlindingCoinCommitment.Equal(&wantBlindingCoinCommitment) {
		t.Fatal("blinding coin commitment mismatch")
	}
	weightedDigitNonce, err := cvWeightedScalarV2(randomness.digitNonces, context.Profile.chunkBits)
	if err != nil {
		t.Fatal(err)
	}
	hShare := cvPointTimes(&h, &randomness.blindingShareNonce)
	wantBlindingCipher := cvPointSum(
		pointPtr(scalarMult(&publicKey, randomness.blindingCoinNonce)), &hShare,
	)
	if !offer.Ownership.BlindingCipherCommitment.Equal(&wantBlindingCipher) {
		t.Fatal("blinding cipher commitment mismatch")
	}
	wantEvaluationCommitment := cvPointSum(pointPtr(scalarMult(&genG1, weightedDigitNonce)), &hShare)
	if !offer.Ownership.EvaluationCommitment.Equal(&wantEvaluationCommitment) {
		t.Fatal("ownership evaluation commitment mismatch")
	}
	if err := cvVerifyOwnershipV2(context, dealer, offer, &publicKey); err != nil {
		t.Fatalf("batched offer does not verify: %v", err)
	}
	recoveredScalar, recoveredBlinding, err := cvVerifyAndDecryptReceiverLanesV2(
		context, dealer, offer, &publicKey, secret,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantOpening := cvPointTimes(&h, &blinding)
	if !recoveredScalar.Equal(&scalar) || !recoveredBlinding.Equal(&wantOpening) {
		t.Fatal("batched offer decryption did not recover the Pedersen opening")
	}
}

// cvEncryptReceiverLanesLegacyV2 preserves the pre-batching implementation for
// equivalence and performance comparison against cvComputeReceiverLaneOfferV2.
func cvEncryptReceiverLanesLegacyV2(
	context *cvLeafContextV2, dealerID, receiverID, receiverIndex int,
	receiverPublicKey *bls12381.G1Affine, scalar, blinding fr.Element,
	randomness *cvReceiverLaneRandomnessV2,
) (*cvReceiverLaneOfferV2, *cvDealerReceiverWitnessV2, error) {
	if err := cvValidateReceiverBindingV2(context, receiverID, receiverIndex, receiverPublicKey); err != nil ||
		dealerID < 0 || randomness == nil {
		return nil, nil, fmt.Errorf("invalid CV V2 receiver lane input")
	}
	scalarDigits, err := cvScalarDigits(scalar, context.Profile)
	if err != nil {
		return nil, nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	offer := &cvReceiverLaneOfferV2{
		ReceiverID: receiverID, ReceiverIndex: receiverIndex,
		ScalarChunks: make([]cvElGamalCiphertext, len(scalarDigits)),
	}
	witness := &cvDealerReceiverWitnessV2{
		ScalarDigits: scalarDigits, ScalarCoins: make([]fr.Element, len(scalarDigits)), Blinding: blinding,
	}
	for chunk, digit := range witness.ScalarDigits {
		witness.ScalarCoins[chunk].Set(&randomness.scalarCoins[chunk])
		var digitPoint bls12381.G1Affine
		digitPoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(digit))
		offer.ScalarChunks[chunk] = cvEncryptPointAfterValidationV2(
			receiverPublicKey, &digitPoint, witness.ScalarCoins[chunk],
		)
	}
	witness.BlindingCoin.Set(&randomness.blindingCoin)
	blindingPoint := cvPointTimes(&h, &blinding)
	offer.Blinding = cvEncryptPointAfterValidationV2(receiverPublicKey, &blindingPoint, witness.BlindingCoin)
	offer.Evaluation = cvPointBaseAndTimes(&scalar, &h, &blinding)
	chunks := len(scalarDigits)
	proof := &cvOwnershipProofV2{
		ScalarCoinCommitments:   make([]bls12381.G1Affine, chunks),
		ScalarCipherCommitments: make([]bls12381.G1Affine, chunks),
		ScalarCoinResponses:     make([]fr.Element, chunks), ScalarDigitResponses: make([]fr.Element, chunks),
	}
	for chunk := 0; chunk < chunks; chunk++ {
		proof.ScalarCoinCommitments[chunk] = cvPointTimes(&genG1, &randomness.coinNonces[chunk])
		proof.ScalarCipherCommitments[chunk] = cvPointBaseAndTimes(
			&randomness.digitNonces[chunk], receiverPublicKey, &randomness.coinNonces[chunk],
		)
	}
	proof.BlindingCoinCommitment = cvPointTimes(&genG1, &randomness.blindingCoinNonce)
	proof.BlindingCipherCommitment = cvPointJointTimes(
		receiverPublicKey, &randomness.blindingCoinNonce, &h, &randomness.blindingShareNonce,
	)
	weightedDigitNonce, err := cvWeightedScalarV2(randomness.digitNonces, context.Profile.chunkBits)
	if err != nil {
		return nil, nil, err
	}
	proof.EvaluationCommitment = cvPointBaseAndTimes(&weightedDigitNonce, &h, &randomness.blindingShareNonce)
	if err := cvFinishOwnershipProofV2(
		context, dealerID, offer, receiverPublicKey, witness, proof,
		randomness.coinNonces, randomness.digitNonces,
		randomness.blindingCoinNonce, randomness.blindingShareNonce,
	); err != nil {
		return nil, nil, err
	}
	offer.Ownership = *proof
	return offer, witness, nil
}

func TestCVReceiverLanesV2BatchedMatchesLegacyImplementation(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	randomness, err := cvGenerateReceiverLaneRandomnessV2(chunks)
	if err != nil {
		t.Fatal(err)
	}
	batched, batchedWitness, err := cvComputeReceiverLaneOfferV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding, randomness,
	)
	if err != nil {
		t.Fatal(err)
	}
	legacy, legacyWitness, err := cvEncryptReceiverLanesLegacyV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding, randomness,
	)
	if err != nil {
		t.Fatal(err)
	}
	batchedWire, err := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealer, batched)
	if err != nil {
		t.Fatal(err)
	}
	legacyWire, err := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealer, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(batchedWire, legacyWire) {
		t.Fatal("batched and legacy receiver lane offers differ on the wire")
	}
	if len(batchedWitness.ScalarCoins) != len(legacyWitness.ScalarCoins) ||
		!batchedWitness.Blinding.Equal(&legacyWitness.Blinding) ||
		!batchedWitness.BlindingCoin.Equal(&legacyWitness.BlindingCoin) {
		t.Fatal("batched and legacy witnesses differ")
	}
	for chunk := range batchedWitness.ScalarCoins {
		if !batchedWitness.ScalarCoins[chunk].Equal(&legacyWitness.ScalarCoins[chunk]) {
			t.Fatalf("witness coin %d differs", chunk)
		}
	}
}
