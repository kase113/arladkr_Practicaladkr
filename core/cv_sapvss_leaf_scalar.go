package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLeafUnsignedWireDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/leaf-unsigned"
	cvLeafWireDomainScalar         = "ARL-CV-sAPVSS/v2-scalar-group/leaf"
	cvLeafDigestDomainScalar       = "ARL-CV-sAPVSS/v2-scalar-group/leaf-digest"
	cvDealerSignatureDomainScalar  = "ARL-CV-sAPVSS/v2-scalar-group/dealer-signature"
	cvLeafEvaluationBatchScalar    = "ARL-CV-sAPVSS/v2-scalar-group/leaf-evaluation-batch"
	cvLeafOwnershipBatchScalar     = "ARL-CV-sAPVSS/v2-scalar-group/leaf-ownership-batch"
)

type cvLeafReceiverScalar struct {
	Offer cvReceiverLaneOfferScalar
	ACK   *cvACKEvidenceScalar
}

type cvLeafScalar struct {
	Context                cvLeafContextScalar
	DealerID               int
	CoefficientCommitments []bls12381.G1Affine
	CoreProof              cvCoreProofScalar
	Receivers              []cvLeafReceiverScalar
	Partition              cvEvidencePartitionScalar
	Fallback               *cvFallbackEvidenceScalar
	DealerSignature        []byte
	Digest                 []byte
	// Decode metadata avoids re-encoding a canonical leaf during verification.
	decodeVerifiedStatement []byte
	decodeCanonicalVerified bool
}

func cvBuildAllACKLeafScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofScalar,
	offers []*cvReceiverLaneOfferScalar, acks []*cvACKEvidenceScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	if context == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) || coreProof == nil {
		return nil, fmt.Errorf("invalid CV V2 all-ACK leaf input")
	}
	partition := cvEvidencePartitionScalar{ACKReceiverIndices: make([]int, len(offers))}
	for i := range offers {
		if offers[i] == nil || acks[i] == nil {
			return nil, fmt.Errorf("all-ACK leaf is missing receiver evidence")
		}
		partition.ACKReceiverIndices[i] = i + 1
	}
	return cvBuildLeafScalar(context, dealerID, commitments, coreProof, offers, acks, &partition, nil, receivers, validators)
}

func cvBuildLeafScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofScalar,
	offers []*cvReceiverLaneOfferScalar, acks []*cvACKEvidenceScalar, partition *cvEvidencePartitionScalar,
	fallback *cvFallbackEvidenceScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	return cvBuildLeafScalarMode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback, receivers, validators, true,
	)
}

func cvBuildLeafScalarMode(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofScalar,
	offers []*cvReceiverLaneOfferScalar, acks []*cvACKEvidenceScalar, partition *cvEvidencePartitionScalar,
	fallback *cvFallbackEvidenceScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
	validateEvidence bool,
) (*cvLeafScalar, error) {
	leaf, _, err := cvBuildLeafMaterialScalarMode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback,
		receivers, validators, validateEvidence,
	)
	return leaf, err
}

func cvBuildLeafMaterialAfterValidationScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofScalar,
	offers []*cvReceiverLaneOfferScalar, acks []*cvACKEvidenceScalar, partition *cvEvidencePartitionScalar,
	fallback *cvFallbackEvidenceScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, []byte, error) {
	return cvBuildLeafMaterialScalarMode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback, receivers, validators, false,
	)
}

func cvBuildLeafMaterialScalarMode(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofScalar,
	offers []*cvReceiverLaneOfferScalar, acks []*cvACKEvidenceScalar, partition *cvEvidencePartitionScalar,
	fallback *cvFallbackEvidenceScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
	validateEvidence bool,
) (*cvLeafScalar, []byte, error) {
	if context == nil || coreProof == nil || partition == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) {
		return nil, nil, fmt.Errorf("invalid CV V2 leaf input")
	}
	if err := cvValidateEvidencePartitionScalar(context, partition); err != nil {
		return nil, nil, err
	}
	if err := cvValidateReceiverMaterialForLeafScalar(context, receivers); err != nil {
		return nil, nil, err
	}
	if err := cvValidateValidatorMaterialForLeafScalar(context, validators); err != nil {
		return nil, nil, err
	}
	leaf := &cvLeafScalar{
		Context: *cvCloneLeafContextScalar(context), DealerID: dealerID,
		CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...), CoreProof: cvCloneCoreProofScalar(coreProof),
		Receivers: make([]cvLeafReceiverScalar, len(offers)),
		Partition: cvEvidencePartitionScalar{
			ACKReceiverIndices:      append([]int(nil), partition.ACKReceiverIndices...),
			FallbackReceiverIndices: append([]int(nil), partition.FallbackReceiverIndices...),
		},
	}
	for i := range offers {
		if offers[i] == nil {
			return nil, nil, fmt.Errorf("CV V2 leaf is missing receiver offer")
		}
		leaf.Receivers[i].Offer = *cvCloneReceiverLaneOfferScalar(offers[i])
		if acks[i] != nil {
			leaf.Receivers[i].ACK = &cvACKEvidenceScalar{
				Ownership: cvCloneOwnershipProofScalar(&acks[i].Ownership), Signature: append([]byte(nil), acks[i].Signature...),
			}
		}
	}
	if fallback != nil {
		if validateEvidence {
			fallbackWire, err := cvFallbackEvidenceScalarCanonicalBytes(fallback, context)
			if err != nil {
				return nil, nil, err
			}
			leaf.Fallback, err = cvDecodeFallbackEvidenceScalar(fallbackWire, context)
			if err != nil {
				return nil, nil, err
			}
		} else {
			leaf.Fallback = cvCloneFallbackEvidenceScalar(fallback)
			if leaf.Fallback == nil {
				return nil, nil, fmt.Errorf("invalid verified CV V2 fallback evidence")
			}
		}
	}
	if validateEvidence {
		if err := cvVerifyLeafStatementScalar(leaf, context, receivers); err != nil {
			return nil, nil, err
		}
	}
	secret, ok := validators.localSecrets[dealerID]
	if !ok {
		return nil, nil, fmt.Errorf("missing local CV V2 dealer signing secret")
	}
	unsigned, err := cvLeafScalarUnsignedCanonicalBytesAfterValidation(leaf, receivers)
	if err != nil {
		return nil, nil, err
	}
	statement := hashBytes([]byte(cvDealerSignatureDomainScalar), unsigned)
	leaf.DealerSignature, err = cvSignValidatorScalar(secret, cvDealerSignatureDomainScalar, statement)
	if err != nil {
		return nil, nil, err
	}
	wire, err := cvLeafScalarCanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		return nil, nil, err
	}
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainScalar), wire)
	return leaf, wire, nil
}

func cvCloneFallbackEvidenceScalar(evidence *cvFallbackEvidenceScalar) *cvFallbackEvidenceScalar {
	if evidence == nil || evidence.Range.proof == nil {
		return nil
	}
	out := &cvFallbackEvidenceScalar{
		ReceiverIndices: append([]int(nil), evidence.ReceiverIndices...),
		Link: cvFallbackLinkProofScalar{
			DigitCommitments:          append([]bls12381.G1Affine(nil), evidence.Link.DigitCommitments...),
			DigitOpeningCommitments:   append([]bls12381.G1Affine(nil), evidence.Link.DigitOpeningCommitments...),
			ScalarCoinCommitments:     append([]bls12381.G1Affine(nil), evidence.Link.ScalarCoinCommitments...),
			ScalarCipherCommitments:   append([]bls12381.G1Affine(nil), evidence.Link.ScalarCipherCommitments...),
			BlindingCoinCommitments:   append([]bls12381.G1Affine(nil), evidence.Link.BlindingCoinCommitments...),
			BlindingCipherCommitments: append([]bls12381.G1Affine(nil), evidence.Link.BlindingCipherCommitments...),
			EvaluationCommitments:     append([]bls12381.G1Affine(nil), evidence.Link.EvaluationCommitments...),
			DigitResponses:            append([]fr.Element(nil), evidence.Link.DigitResponses...),
			DigitBlindResponses:       append([]fr.Element(nil), evidence.Link.DigitBlindResponses...),
			ScalarCoinResponses:       append([]fr.Element(nil), evidence.Link.ScalarCoinResponses...),
			BlindingCoinResponses:     append([]fr.Element(nil), evidence.Link.BlindingCoinResponses...),
			BlindingShareResponses:    append([]fr.Element(nil), evidence.Link.BlindingShareResponses...),
		},
	}
	compact := *evidence.Range.proof
	compact.inner.left = append([]bls12381.G1Affine(nil), evidence.Range.proof.inner.left...)
	compact.inner.right = append([]bls12381.G1Affine(nil), evidence.Range.proof.inner.right...)
	out.Range = cvFallbackRangeProofScalar{backend: evidence.Range.backend, proof: &compact}
	return out
}

// cvVerifyAPVSSScalar is the unique verifier for both ACK and fallback evidence.
func cvVerifyAPVSSScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) error {
	return cvVerifyAPVSSModeScalar(leaf, expectedContext, receivers, validators, true)
}

func cvVerifyAPVSSAfterPointDecodingScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) error {
	return cvVerifyAPVSSModeScalar(leaf, expectedContext, receivers, validators, false)
}

func cvVerifyAPVSSModeScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
	validatePoints bool,
) error {
	if leaf == nil {
		return fmt.Errorf("nil CV V2 leaf")
	}
	var statementErr error
	if validatePoints {
		statementErr = cvVerifyLeafStatementScalar(leaf, expectedContext, receivers)
	} else {
		statementErr = cvVerifyLeafStatementAfterPointDecodingScalar(leaf, expectedContext, receivers)
	}
	if statementErr != nil {
		return statementErr
	}
	if err := cvValidateValidatorMaterialForLeafScalar(expectedContext, validators); err != nil {
		return err
	}
	dealerIndex, ok := validators.memberIndex[leaf.DealerID]
	if !ok {
		return fmt.Errorf("CV V2 dealer is outside validator registry")
	}
	statement := leaf.decodeVerifiedStatement
	if statement == nil {
		unsigned, err := cvLeafScalarUnsignedCanonicalBytesAfterValidation(leaf, receivers)
		if err != nil {
			return err
		}
		statement = hashBytes([]byte(cvDealerSignatureDomainScalar), unsigned)
	}
	if !cvVerifyValidatorSignatureScalar(
		&validators.publicKeys[dealerIndex], cvDealerSignatureDomainScalar, statement, leaf.DealerSignature,
	) {
		return fmt.Errorf("invalid CV V2 dealer signature")
	}
	if leaf.decodeCanonicalVerified {
		// The decode path already proved the full wire canonical and derived
		// the digest from it; re-encoding megabytes per leaf is pure overhead.
		if len(leaf.Digest) != 32 {
			return fmt.Errorf("invalid CV V2 leaf digest")
		}
		return nil
	}
	wire, err := cvLeafScalarCanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		return err
	}
	expectedDigest := hashBytes([]byte(cvLeafDigestDomainScalar), wire)
	if len(leaf.Digest) != 32 || !bytes.Equal(leaf.Digest, expectedDigest) {
		return fmt.Errorf("invalid CV V2 leaf digest")
	}
	return nil
}

func cvVerifyLeafStatementScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar, receivers *cvReceiverKeyMaterialScalar,
) error {
	return cvVerifyLeafStatementModeScalar(leaf, expectedContext, receivers, true)
}

func cvVerifyLeafStatementAfterPointDecodingScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar, receivers *cvReceiverKeyMaterialScalar,
) error {
	return cvVerifyLeafStatementModeScalar(leaf, expectedContext, receivers, false)
}

func cvVerifyReceiverEvaluationsExactScalar(
	commitments []bls12381.G1Affine, evaluations []bls12381.G1Affine,
) error {
	for index := range evaluations {
		expected := cvEvaluateCommitments(commitments, index+1)
		if !evaluations[index].Equal(&expected) {
			return fmt.Errorf("CV V2 receiver %d evaluation does not match coefficient polynomial", index+1)
		}
	}
	return nil
}

func cvVerifyReceiverEvaluationsBatchScalar(
	context *cvLeafContextScalar, dealerID int, commitments, evaluations []bls12381.G1Affine,
	validatePoints bool,
) error {
	if context == nil || dealerID < 0 || len(commitments) == 0 || len(evaluations) != len(context.NewRoster) {
		return fmt.Errorf("invalid CV V2 receiver evaluation batch")
	}
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return err
	}
	var statement bytes.Buffer
	_ = cvWriteBytes(&statement, contextWire)
	cvWriteUint64(&statement, uint64(dealerID))
	if err := cvWritePointVectorMode(&statement, commitments, validatePoints); err != nil {
		return fmt.Errorf("invalid CV V2 receiver evaluation commitments: %w", err)
	}
	if err := cvWritePointVectorMode(&statement, evaluations, validatePoints); err != nil {
		return fmt.Errorf("invalid CV V2 receiver evaluations: %w", err)
	}
	challenge, err := cvHashToFr(cvLeafEvaluationBatchScalar, statement.Bytes())
	if err != nil {
		return err
	}
	if challenge.IsZero() {
		challenge, err = cvHashToFr(cvLeafEvaluationBatchScalar, statement.Bytes(), []byte("nonzero"))
		if err != nil {
			return err
		}
		if challenge.IsZero() {
			return fmt.Errorf("zero CV V2 receiver evaluation batch challenge")
		}
	}
	weights := cvFrPowers(challenge, len(evaluations))
	powers := cvEvaluationPowers(len(commitments), len(evaluations))
	commitmentWeights := make([]fr.Element, len(commitments))
	// Check sum_u r_u*V_u = sum_v (sum_u r_u*u^v)*A_v with two MSMs.
	for receiver := range evaluations {
		for coefficient := range commitments {
			var term fr.Element
			term.Mul(&weights[receiver], &powers[receiver][coefficient])
			commitmentWeights[coefficient].Add(&commitmentWeights[coefficient], &term)
		}
	}
	combinedEvaluations := cvEvaluateCommitmentsWithPowers(evaluations, weights)
	combinedCommitments := cvEvaluateCommitmentsWithPowers(commitments, commitmentWeights)
	if combinedEvaluations.Equal(&combinedCommitments) {
		return nil
	}
	if err := cvVerifyReceiverEvaluationsExactScalar(commitments, evaluations); err != nil {
		return err
	}
	return fmt.Errorf("CV V2 receiver evaluation batch mismatch")
}

func cvVerifyOwnershipBatchScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, validatePoints bool,
) error {
	if context == nil || dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) {
		return fmt.Errorf("invalid CV V2 ownership batch")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return err
	}
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return err
	}
	var statement bytes.Buffer
	_ = cvWriteBytes(&statement, contextWire)
	cvWriteUint64(&statement, uint64(dealerID))
	if err := cvWriteUint32(&statement, len(offers)); err != nil {
		return err
	}
	ownershipChallenges := make([]fr.Element, len(offers))
	for i, offer := range offers {
		var shapeErr error
		if validatePoints {
			shapeErr = cvValidateLaneOfferShapeScalar(context, offer, &receiverPublicKeys[i])
		} else {
			shapeErr = cvValidateLaneOfferShapeAfterPointDecodingScalar(context, offer, &receiverPublicKeys[i])
		}
		if shapeErr != nil {
			return fmt.Errorf("invalid CV V2 ownership batch receiver %d statement", offer.ReceiverIndex)
		}
		proof := &offer.Ownership
		if len(proof.ScalarCoinCommitments) != chunks || len(proof.ScalarCipherCommitments) != chunks ||
			len(proof.ScalarCoinResponses) != chunks || len(proof.ScalarDigitResponses) != chunks {
			return fmt.Errorf("invalid CV V2 ownership batch receiver %d proof dimensions", offer.ReceiverIndex)
		}
		if validatePoints {
			for chunk := 0; chunk < chunks; chunk++ {
				if !cvValidG1(&proof.ScalarCoinCommitments[chunk], true) ||
					!cvValidG1(&proof.ScalarCipherCommitments[chunk], true) {
					return fmt.Errorf("invalid CV V2 ownership batch receiver %d proof point", offer.ReceiverIndex)
				}
			}
			if !cvValidG1(&proof.BlindingCoinCommitment, true) ||
				!cvValidG1(&proof.BlindingCipherCommitment, true) ||
				!cvValidG1(&proof.EvaluationCommitment, true) {
				return fmt.Errorf("invalid CV V2 ownership batch receiver %d proof point", offer.ReceiverIndex)
			}
		}
		ownershipChallenges[i], err = cvOwnershipChallengeScalarAfterValidationScalar(
			context, dealerID, offer, &receiverPublicKeys[i], proof,
		)
		if err != nil {
			return err
		}
		cvWritePoint(&statement, &receiverPublicKeys[i])
		offerWire, wireErr := cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(context, dealerID, offer)
		if wireErr != nil {
			return wireErr
		}
		_ = cvWriteBytes(&statement, offerWire)
	}
	batchChallenge, err := cvHashToFr(cvLeafOwnershipBatchScalar, statement.Bytes())
	if err != nil {
		return err
	}
	if batchChallenge.IsZero() {
		batchChallenge, err = cvHashToFr(cvLeafOwnershipBatchScalar, statement.Bytes(), []byte("nonzero"))
		if err != nil {
			return err
		}
		if batchChallenge.IsZero() {
			return fmt.Errorf("zero CV V2 ownership batch challenge")
		}
	}

	equationCount := len(offers) * (2*chunks + 3)
	weights := make([]fr.Element, equationCount)
	weights[0] = batchChallenge
	for i := 1; i < equationCount; i++ {
		weights[i].Mul(&weights[i-1], &batchChallenge)
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	points := make([]bls12381.G1Affine, 0, 2*equationCount+len(offers)+2)
	scalars := make([]fr.Element, 0, cap(points))
	appendNegative := func(point *bls12381.G1Affine, scalar *fr.Element) {
		var negative fr.Element
		negative.Neg(scalar)
		points = append(points, *point)
		scalars = append(scalars, negative)
	}
	appendNegativeProduct := func(point *bls12381.G1Affine, first, second *fr.Element) {
		var product fr.Element
		product.Mul(first, second).Neg(&product)
		points = append(points, *point)
		scalars = append(scalars, product)
	}
	var generatorScalar, pedersenScalar fr.Element
	publicKeyScalars := make([]fr.Element, len(offers))
	weightIndex := 0
	for i, offer := range offers {
		proof := &offer.Ownership
		challenge := &ownershipChallenges[i]
		for chunk := 0; chunk < chunks; chunk++ {
			coinWeight := &weights[weightIndex]
			weightIndex++
			var term fr.Element
			term.Mul(coinWeight, &proof.ScalarCoinResponses[chunk])
			generatorScalar.Add(&generatorScalar, &term)
			appendNegative(&proof.ScalarCoinCommitments[chunk], coinWeight)
			appendNegativeProduct(&offer.ScalarChunks[chunk].r, coinWeight, challenge)

			cipherWeight := &weights[weightIndex]
			weightIndex++
			term.Mul(cipherWeight, &proof.ScalarDigitResponses[chunk])
			generatorScalar.Add(&generatorScalar, &term)
			term.Mul(cipherWeight, &proof.ScalarCoinResponses[chunk])
			publicKeyScalars[i].Add(&publicKeyScalars[i], &term)
			appendNegative(&proof.ScalarCipherCommitments[chunk], cipherWeight)
			appendNegativeProduct(&offer.ScalarChunks[chunk].c, cipherWeight, challenge)
		}

		blindingCoinWeight := &weights[weightIndex]
		weightIndex++
		var term fr.Element
		term.Mul(blindingCoinWeight, &proof.BlindingCoinResponse)
		generatorScalar.Add(&generatorScalar, &term)
		appendNegative(&proof.BlindingCoinCommitment, blindingCoinWeight)
		appendNegativeProduct(&offer.Blinding.r, blindingCoinWeight, challenge)

		blindingCipherWeight := &weights[weightIndex]
		weightIndex++
		term.Mul(blindingCipherWeight, &proof.BlindingCoinResponse)
		publicKeyScalars[i].Add(&publicKeyScalars[i], &term)
		term.Mul(blindingCipherWeight, &proof.BlindingShareResponse)
		pedersenScalar.Add(&pedersenScalar, &term)
		appendNegative(&proof.BlindingCipherCommitment, blindingCipherWeight)
		appendNegativeProduct(&offer.Blinding.c, blindingCipherWeight, challenge)

		evaluationWeight := &weights[weightIndex]
		weightIndex++
		weightedResponse, weightedErr := cvWeightedScalarScalar(
			proof.ScalarDigitResponses, context.Profile.chunkBits,
		)
		if weightedErr != nil {
			return weightedErr
		}
		term.Mul(evaluationWeight, &weightedResponse)
		generatorScalar.Add(&generatorScalar, &term)
		term.Mul(evaluationWeight, &proof.BlindingShareResponse)
		pedersenScalar.Add(&pedersenScalar, &term)
		appendNegative(&proof.EvaluationCommitment, evaluationWeight)
		appendNegativeProduct(&offer.Evaluation, evaluationWeight, challenge)
	}
	points = append(points, genG1, h)
	scalars = append(scalars, generatorScalar, pedersenScalar)
	for i := range receiverPublicKeys {
		points = append(points, receiverPublicKeys[i])
		scalars = append(scalars, publicKeyScalars[i])
	}
	combined, err := cvG1LinearCombination(points, scalars)
	if err != nil {
		return err
	}
	var identity fr.Element
	zero := cvPointTimes(&genG1, &identity)
	if combined.Equal(&zero) {
		return nil
	}
	for i, offer := range offers {
		if err := cvVerifyOwnershipModeScalar(
			context, dealerID, offer, &receiverPublicKeys[i], validatePoints,
		); err != nil {
			return fmt.Errorf("invalid CV V2 ownership batch receiver %d: %w", offer.ReceiverIndex, err)
		}
	}
	return fmt.Errorf("CV V2 ownership batch mismatch")
}

func cvVerifyLeafStatementModeScalar(
	leaf *cvLeafScalar, expectedContext *cvLeafContextScalar, receivers *cvReceiverKeyMaterialScalar,
	validatePoints bool,
) error {
	if leaf == nil || expectedContext == nil || leaf.DealerID < 0 ||
		len(leaf.CoefficientCommitments) != expectedContext.SharingDegree+1 ||
		len(leaf.Receivers) != len(expectedContext.NewRoster) ||
		cvValidateReceiverMaterialForLeafScalar(expectedContext, receivers) != nil {
		return fmt.Errorf("invalid CV V2 leaf statement")
	}
	expectedContextWire, err := cvLeafContextScalarCanonicalBytes(expectedContext)
	if err != nil {
		return err
	}
	actualContextWire, err := cvLeafContextScalarCanonicalBytes(&leaf.Context)
	if err != nil || !bytes.Equal(actualContextWire, expectedContextWire) {
		return fmt.Errorf("CV V2 leaf context mismatch")
	}
	if !cvMemberInRosterScalar(leaf.DealerID, expectedContext.OldRoster) {
		return fmt.Errorf("CV V2 leaf dealer is outside old roster")
	}
	var coreErr error
	if validatePoints {
		coreErr = cvVerifyCoreScalar(expectedContext, leaf.DealerID, leaf.CoefficientCommitments, &leaf.CoreProof)
	} else {
		coreErr = cvVerifyCoreAfterPointDecodingScalar(
			expectedContext, leaf.DealerID, leaf.CoefficientCommitments, &leaf.CoreProof,
		)
	}
	if coreErr != nil {
		return coreErr
	}
	if err := cvValidateEvidencePartitionScalar(expectedContext, &leaf.Partition); err != nil {
		return err
	}
	fallbackSet := make(map[int]struct{}, len(leaf.Partition.FallbackReceiverIndices))
	for _, index := range leaf.Partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	fallbackOffers := make([]*cvReceiverLaneOfferScalar, 0, len(fallbackSet))
	fallbackKeys := make([]bls12381.G1Affine, 0, len(fallbackSet))
	ackOffers := make([]*cvReceiverLaneOfferScalar, 0, len(leaf.Receivers)-len(fallbackSet))
	ackKeys := make([]bls12381.G1Affine, 0, len(leaf.Receivers)-len(fallbackSet))
	ackReceiverIndices := make([]int, 0, len(leaf.Receivers)-len(fallbackSet))
	evaluations := make([]bls12381.G1Affine, len(leaf.Receivers))
	for i := range leaf.Receivers {
		receiver := &leaf.Receivers[i]
		expectedID := expectedContext.NewRoster[i]
		if receiver.Offer.ReceiverID != expectedID || receiver.Offer.ReceiverIndex != i+1 {
			return fmt.Errorf("invalid CV V2 leaf receiver ordering")
		}
		evaluations[i] = receiver.Offer.Evaluation
	}
	if err := cvVerifyReceiverEvaluationsBatchScalar(
		expectedContext, leaf.DealerID, leaf.CoefficientCommitments, evaluations, validatePoints,
	); err != nil {
		return err
	}
	for i := range leaf.Receivers {
		receiver := &leaf.Receivers[i]
		if _, isFallback := fallbackSet[i+1]; isFallback {
			if receiver.ACK != nil {
				return fmt.Errorf("CV V2 fallback receiver also carries ACK evidence")
			}
			fallbackOffers = append(fallbackOffers, &receiver.Offer)
			fallbackKeys = append(fallbackKeys, receivers.encryptionPublicKeys[i])
		} else {
			if receiver.ACK == nil {
				return fmt.Errorf("CV V2 ACK receiver is missing evidence")
			}
			ackOffers = append(ackOffers, &receiver.Offer)
			ackKeys = append(ackKeys, receivers.encryptionPublicKeys[i])
			ackReceiverIndices = append(ackReceiverIndices, i)
		}
	}
	if len(ackOffers) != 0 {
		if err := cvVerifyOwnershipBatchScalar(
			expectedContext, leaf.DealerID, ackOffers, ackKeys, validatePoints,
		); err != nil {
			return err
		}
	}
	for _, i := range ackReceiverIndices {
		receiver := &leaf.Receivers[i]
		if err := cvVerifyACKAfterLocalOwnershipValidationScalar(
			expectedContext, leaf.DealerID, &receiver.Offer,
			receivers.identityPublicKeys[i], receiver.ACK,
		); err != nil {
			return fmt.Errorf("invalid CV V2 receiver %d ACK: %w", i+1, err)
		}
	}
	if len(fallbackOffers) == 0 {
		if leaf.Fallback != nil {
			return fmt.Errorf("all-ACK CV V2 leaf carries fallback evidence")
		}
	} else {
		var fallbackErr error
		if validatePoints {
			fallbackErr = cvVerifyFallbackEvidenceScalar(
				expectedContext, leaf.DealerID, fallbackOffers, fallbackKeys, leaf.Fallback,
			)
		} else {
			fallbackErr = cvVerifyFallbackEvidenceAfterPointDecodingScalar(
				expectedContext, leaf.DealerID, fallbackOffers, fallbackKeys, leaf.Fallback,
			)
		}
		if fallbackErr != nil {
			return fmt.Errorf("invalid CV V2 fallback evidence: %w", fallbackErr)
		}
	}
	return nil
}

func cvLeafScalarUnsignedCanonicalBytes(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar,
) ([]byte, error) {
	return cvLeafScalarUnsignedCanonicalBytesMode(leaf, receivers, true, 0)
}

func cvLeafScalarUnsignedCanonicalBytesAfterValidation(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar,
) ([]byte, error) {
	return cvLeafScalarUnsignedCanonicalBytesMode(leaf, receivers, false, 0)
}

// cvLeafScalarUnsignedCanonicalBytesSized preallocates a canonical encoding buffer.
func cvLeafScalarUnsignedCanonicalBytesSized(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, sizeHint int,
) ([]byte, error) {
	return cvLeafScalarUnsignedCanonicalBytesMode(leaf, receivers, false, sizeHint)
}

func cvLeafScalarUnsignedCanonicalBytesMode(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, validateEvidence bool, sizeHint int,
) ([]byte, error) {
	if leaf == nil || cvValidateReceiverMaterialForLeafScalar(&leaf.Context, receivers) != nil ||
		cvValidateEvidencePartitionScalar(&leaf.Context, &leaf.Partition) != nil ||
		len(leaf.Receivers) != len(leaf.Context.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf")
	}
	contextWire, err := cvLeafContextScalarCanonicalBytes(&leaf.Context)
	if err != nil {
		return nil, err
	}
	var coreWire []byte
	if validateEvidence {
		coreWire, err = cvCoreProofScalarCanonicalBytes(&leaf.CoreProof, len(leaf.CoefficientCommitments))
	} else {
		coreWire, err = cvCoreProofScalarCanonicalBytesAfterValidation(&leaf.CoreProof, len(leaf.CoefficientCommitments))
	}
	if err != nil {
		return nil, err
	}
	partitionWire, err := cvEvidencePartitionScalarCanonicalBytes(&leaf.Context, &leaf.Partition)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if sizeHint > 0 {
		wire.Grow(sizeHint)
	}
	_ = cvWriteBytes(&wire, []byte(cvLeafUnsignedWireDomainScalar))
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(leaf.DealerID))
	if err := cvWritePointVectorMode(&wire, leaf.CoefficientCommitments, validateEvidence); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, coreWire)
	_ = cvWriteBytes(&wire, partitionWire)
	if err := cvWriteUint32(&wire, len(leaf.Receivers)); err != nil {
		return nil, err
	}
	fallbackSet := make(map[int]struct{}, len(leaf.Partition.FallbackReceiverIndices))
	for _, index := range leaf.Partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	for i := range leaf.Receivers {
		receiver := &leaf.Receivers[i]
		if _, isFallback := fallbackSet[i+1]; isFallback {
			if receiver.ACK != nil || cvWriteUint32(&wire, 1) != nil {
				return nil, fmt.Errorf("invalid CV V2 fallback receiver wire")
			}
			var offerWire []byte
			var err error
			if validateEvidence {
				offerWire, err = cvFallbackLaneOfferScalarCanonicalBytes(
					&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
				)
			} else {
				offerWire, err = cvFallbackLaneOfferScalarCanonicalBytesAfterValidation(
					&leaf.Context, leaf.DealerID, &receiver.Offer,
				)
			}
			if err != nil {
				return nil, err
			}
			_ = cvWriteBytes(&wire, offerWire)
		} else {
			if receiver.ACK == nil || cvWriteUint32(&wire, 0) != nil {
				return nil, fmt.Errorf("invalid CV V2 ACK receiver wire")
			}
			var offerWire, ackWire []byte
			var err error
			if validateEvidence {
				offerWire, err = cvReceiverLaneOfferScalarCanonicalBytes(
					&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
				)
			} else {
				offerWire, err = cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(
					&leaf.Context, leaf.DealerID, &receiver.Offer,
				)
			}
			if err != nil {
				return nil, err
			}
			if validateEvidence {
				ackWire, err = cvACKEvidenceScalarCanonicalBytes(receiver.ACK, &leaf.Context)
			} else {
				ackWire, err = cvACKEvidenceScalarCanonicalBytesAfterValidation(receiver.ACK, &leaf.Context)
			}
			if err != nil {
				return nil, err
			}
			_ = cvWriteBytes(&wire, offerWire)
			_ = cvWriteBytes(&wire, ackWire)
		}
	}
	if len(fallbackSet) == 0 {
		if leaf.Fallback != nil {
			return nil, fmt.Errorf("unexpected CV V2 fallback evidence")
		}
		_ = cvWriteBytes(&wire, nil)
	} else {
		var fallbackWire []byte
		var err error
		if validateEvidence {
			fallbackWire, err = cvFallbackEvidenceScalarCanonicalBytes(leaf.Fallback, &leaf.Context)
		} else {
			fallbackWire, err = cvFallbackEvidenceScalarCanonicalBytesAfterValidation(leaf.Fallback, &leaf.Context)
		}
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&wire, fallbackWire)
	}
	return wire.Bytes(), nil
}

func cvLeafScalarCanonicalBytes(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) ([]byte, error) {
	return cvLeafScalarCanonicalBytesMode(leaf, receivers, validators, true, 0)
}

func cvLeafScalarCanonicalBytesAfterValidation(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) ([]byte, error) {
	return cvLeafScalarCanonicalBytesMode(leaf, receivers, validators, false, 0)
}

// cvLeafScalarCanonicalBytesSized is the decode-path variant: the caller knows the
// wire length the canonical encoding must reproduce, so both assembly buffers
// are allocated once instead of doubling through megabytes per leaf.
func cvLeafScalarCanonicalBytesSized(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
	sizeHint int,
) ([]byte, error) {
	return cvLeafScalarCanonicalBytesMode(leaf, receivers, validators, false, sizeHint)
}

func cvLeafScalarCanonicalBytesMode(
	leaf *cvLeafScalar, receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
	validateEvidence bool, sizeHint int,
) ([]byte, error) {
	if leaf == nil || len(leaf.DealerSignature) != bls12381.SizeOfG1AffineCompressed ||
		cvValidateValidatorMaterialForLeafScalar(&leaf.Context, validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf wire")
	}
	var unsigned []byte
	var err error
	unsignedHint := 0
	if sizeHint > 64 {
		unsignedHint = sizeHint - 64
	}
	if validateEvidence {
		unsigned, err = cvLeafScalarUnsignedCanonicalBytes(leaf, receivers)
	} else {
		unsigned, err = cvLeafScalarUnsignedCanonicalBytesSized(leaf, receivers, unsignedHint)
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if sizeHint > 0 {
		wire.Grow(sizeHint)
	}
	_ = cvWriteBytes(&wire, []byte(cvLeafWireDomainScalar))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, leaf.DealerSignature)
	return wire.Bytes(), nil
}

func cvDecodeLeafScalar(
	wire []byte, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	return cvDecodeLeafScalarSidechannel(wire, nil, expectedContext, receivers, validators)
}

// cvDecodeLeafScalarWithHints decodes with an optional uncompressed-point
// attachment. Hints only change how y-coordinates are obtained; every
// accepted point still recompresses to the exact signed wire bytes.
func cvDecodeLeafScalarWithHints(
	wire, hints []byte, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	return cvDecodeLeafScalarSidechannel(
		wire, newCVDecodeSidechannelHintsScalar(hints), expectedContext, receivers, validators,
	)
}

// cvRecordLeafDeferredHintsScalar decodes exactly as consumers will and records
// the uncompressed form of every deferred point in wire order. A nil result
// means the decode rejected the wire, so no attachment is served.
func cvRecordLeafDeferredHintsScalar(
	wire []byte, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) []byte {
	side := newCVDecodeSidechannelRecordingScalar()
	if _, err := cvDecodeLeafScalarSidechannel(wire, side, expectedContext, receivers, validators); err != nil {
		return nil
	}
	return side.record
}

func cvDecodeLeafScalarSidechannel(
	wire []byte, side *cvDecodeSidechannelScalar, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	// A leaf decode always owns a sidechannel: with no hints it exists purely
	// to collect every deferred point for one leaf-wide subgroup batch.
	if side == nil {
		side = &cvDecodeSidechannelScalar{collectSubgroup: true}
	} else {
		side.collectSubgroup = true
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLeafWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 leaf domain")
	}
	unsigned, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf framing")
	}
	signature, err := r.bytes(bls12381.SizeOfG1AffineCompressed)
	if err != nil || len(signature) != bls12381.SizeOfG1AffineCompressed || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 dealer signature framing")
	}
	leaf, err := cvDecodeLeafScalarUnsignedSidechannel(unsigned, side, expectedContext, receivers)
	if err != nil {
		return nil, err
	}
	// One leaf-wide subgroup batch replaces the per-section checks; the leaf
	// is rejected here before any structure escapes to the caller.
	if err := side.finishDeferredSubgroupBatch(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf point: %w", err)
	}
	leaf.DealerSignature = signature
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainScalar), wire)
	// Hash the framed unsigned span directly instead of re-encoding the leaf.
	unsignedOffset := 4 + len(cvLeafWireDomainScalar) + 4
	unsignedWire := wire[unsignedOffset : unsignedOffset+len(unsigned)]
	leaf.decodeVerifiedStatement = hashBytes([]byte(cvDealerSignatureDomainScalar), unsignedWire)
	canonical, err := cvLeafScalarCanonicalBytesSized(leaf, receivers, validators, len(wire))
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 leaf")
	}
	leaf.decodeCanonicalVerified = true
	if err := cvVerifyAPVSSAfterPointDecodingScalar(leaf, expectedContext, receivers, validators); err != nil {
		return nil, err
	}
	return leaf, nil
}

func cvDecodeLeafScalarUnsignedSidechannel(
	wire []byte, side *cvDecodeSidechannelScalar, expectedContext *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar,
) (*cvLeafScalar, error) {
	if cvValidateReceiverMaterialForLeafScalar(expectedContext, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf receiver registry")
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvLeafUnsignedWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafUnsignedWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf domain")
	}
	contextWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	context, err := cvDecodeLeafContextScalar(contextWire)
	if err != nil {
		return nil, err
	}
	expectedWire, err := cvLeafContextScalarCanonicalBytes(expectedContext)
	if err != nil || !bytes.Equal(contextWire, expectedWire) {
		return nil, fmt.Errorf("CV V2 unsigned leaf context mismatch")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 leaf dealer")
	}
	commitments, err := cvReadExactPointVectorDeferred(
		r, expectedContext.SharingDegree+1, "V2 coefficient commitments",
	)
	if err != nil {
		return nil, err
	}
	coreWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, err
	}
	coreProof, err := cvDecodeCoreProofScalarSidechannel(coreWire, len(commitments), side)
	if err != nil {
		return nil, err
	}
	partitionWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	partition, err := cvDecodeEvidencePartitionScalar(partitionWire, expectedContext)
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != len(expectedContext.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 receiver transcript count")
	}
	leaf := &cvLeafScalar{
		Context: *context, DealerID: int(dealer), CoefficientCommitments: commitments,
		CoreProof: *coreProof, Partition: *partition, Receivers: make([]cvLeafReceiverScalar, count),
	}
	fallbackSet := make(map[int]struct{}, len(partition.FallbackReceiverIndices))
	for _, index := range partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	for i := 0; i < count; i++ {
		mode, err := r.uint32()
		_, isFallback := fallbackSet[i+1]
		wantMode := 0
		if isFallback {
			wantMode = 1
		}
		if err != nil || mode != wantMode {
			return nil, fmt.Errorf("invalid CV V2 receiver evidence mode")
		}
		offerWire, err := r.bytes(cvMaxLeafWireBytes)
		if err != nil {
			return nil, err
		}
		var offer *cvReceiverLaneOfferScalar
		if isFallback {
			offer, err = cvDecodeFallbackLaneOfferScalar(
				offerWire, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
			)
		} else {
			offer, err = cvDecodeReceiverLaneOfferBeforeVerificationScalarSidechannel(
				offerWire, side, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
				&receivers.encryptionPublicKeys[i],
			)
		}
		if err != nil {
			return nil, err
		}
		leaf.Receivers[i] = cvLeafReceiverScalar{Offer: *offer}
		if !isFallback {
			ackWire, readErr := r.bytes(cvMaxLeafProofWireBytes)
			if readErr != nil {
				return nil, readErr
			}
			ack, readErr := cvDecodeACKEvidenceScalarSidechannel(ackWire, side, expectedContext)
			if readErr != nil {
				return nil, readErr
			}
			leaf.Receivers[i].ACK = ack
		}
	}
	fallbackWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence framing")
	}
	if len(fallbackSet) == 0 {
		if len(fallbackWire) != 0 {
			return nil, fmt.Errorf("all-ACK CV V2 leaf carries fallback evidence")
		}
	} else {
		leaf.Fallback, err = cvDecodeFallbackEvidenceScalar(fallbackWire, expectedContext)
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 unsigned leaf bytes")
	}
	if err := r.assertDecodedSubgroup(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf coefficient point: %w", err)
	}
	canonical, err := cvLeafScalarUnsignedCanonicalBytesAfterValidation(leaf, receivers)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 unsigned leaf")
	}
	return leaf, nil
}

func cvValidateReceiverMaterialForLeafScalar(
	context *cvLeafContextScalar, material *cvReceiverKeyMaterialScalar,
) error {
	if context == nil || material == nil || material.sid != context.SID || material.epoch != context.Epoch ||
		!equalInts(material.receiverOrder, context.NewRoster) ||
		len(material.encryptionPublicKeys) != len(context.NewRoster) ||
		len(material.identityPublicKeys) != len(context.NewRoster) ||
		!bytes.Equal(material.registryDigest, context.ReceiverRegistryDigest) {
		return fmt.Errorf("CV V2 receiver registry does not match leaf context")
	}
	return nil
}

func cvValidateValidatorMaterialForLeafScalar(
	context *cvLeafContextScalar, material *cvValidatorKeyMaterialScalar,
) error {
	if context == nil || material == nil || material.sid != context.SID || material.epoch != context.Epoch ||
		!equalInts(material.memberOrder, context.OldRoster) ||
		len(material.publicKeys) != len(context.OldRoster) {
		return fmt.Errorf("CV V2 validator registry does not match leaf context")
	}
	return nil
}

func cvCloneLeafContextScalar(context *cvLeafContextScalar) *cvLeafContextScalar {
	if context == nil {
		return nil
	}
	cloned := *context
	cloned.OldRoster = append([]int(nil), context.OldRoster...)
	cloned.NewRoster = append([]int(nil), context.NewRoster...)
	cloned.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	return &cloned
}

func cvCloneCoreProofScalar(proof *cvCoreProofScalar) cvCoreProofScalar {
	if proof == nil {
		return cvCoreProofScalar{}
	}
	return cvCoreProofScalar{
		NonceCommitments:  append([]bls12381.G1Affine(nil), proof.NonceCommitments...),
		ScalarResponses:   append([]fr.Element(nil), proof.ScalarResponses...),
		BlindingResponses: append([]fr.Element(nil), proof.BlindingResponses...),
	}
}

func cvCloneReceiverLaneOfferScalar(offer *cvReceiverLaneOfferScalar) *cvReceiverLaneOfferScalar {
	if offer == nil {
		return nil
	}
	cloned := *offer
	cloned.ScalarChunks = append([]cvElGamalCiphertext(nil), offer.ScalarChunks...)
	cloned.Blinding = offer.Blinding
	cloned.Ownership = cvCloneOwnershipProofScalar(&offer.Ownership)
	return &cloned
}
