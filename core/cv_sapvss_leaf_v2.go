package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLeafUnsignedWireDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/leaf-unsigned"
	cvLeafWireDomainV2         = "ARL-CV-sAPVSS/v2-scalar-group/leaf"
	cvLeafDigestDomainV2       = "ARL-CV-sAPVSS/v2-scalar-group/leaf-digest"
	cvDealerSignatureDomainV2  = "ARL-CV-sAPVSS/v2-scalar-group/dealer-signature"
	cvLeafEvaluationBatchV2    = "ARL-CV-sAPVSS/v2-scalar-group/leaf-evaluation-batch"
	cvLeafOwnershipBatchV2     = "ARL-CV-sAPVSS/v2-scalar-group/leaf-ownership-batch"
)

type cvLeafReceiverV2 struct {
	Offer cvReceiverLaneOfferV2
	ACK   *cvACKEvidenceV2
}

type cvLeafV2 struct {
	Context                cvLeafContextV2
	DealerID               int
	CoefficientCommitments []bls12381.G1Affine
	CoreProof              cvCoreProofV2
	Receivers              []cvLeafReceiverV2
	Partition              cvEvidencePartitionV2
	Fallback               *cvFallbackEvidenceV2
	DealerSignature        []byte
	Digest                 []byte
	// decodeVerifiedStatement is the dealer-signature statement hash computed
	// from the canonical wire during decoding, and decodeCanonicalVerified
	// records that the full wire already passed the canonical-bytes check.
	// Together they let the APVSS verifier skip re-encoding megabyte wires per
	// leaf; locally built leaves leave them unset and take the encode path.
	decodeVerifiedStatement []byte
	decodeCanonicalVerified bool
}

func cvBuildAllACKLeafV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	if context == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) || coreProof == nil {
		return nil, fmt.Errorf("invalid CV V2 all-ACK leaf input")
	}
	partition := cvEvidencePartitionV2{ACKReceiverIndices: make([]int, len(offers))}
	for i := range offers {
		if offers[i] == nil || acks[i] == nil {
			return nil, fmt.Errorf("all-ACK leaf is missing receiver evidence")
		}
		partition.ACKReceiverIndices[i] = i + 1
	}
	return cvBuildLeafV2(context, dealerID, commitments, coreProof, offers, acks, &partition, nil, receivers, validators)
}

func cvBuildLeafV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	return cvBuildLeafV2Mode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback, receivers, validators, true,
	)
}

func cvBuildLeafAfterValidationV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	return cvBuildLeafV2Mode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback, receivers, validators, false,
	)
}

func cvBuildLeafV2Mode(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	validateEvidence bool,
) (*cvLeafV2, error) {
	leaf, _, err := cvBuildLeafMaterialV2Mode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback,
		receivers, validators, validateEvidence,
	)
	return leaf, err
}

func cvBuildLeafMaterialAfterValidationV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, []byte, error) {
	return cvBuildLeafMaterialV2Mode(
		context, dealerID, commitments, coreProof, offers, acks, partition, fallback, receivers, validators, false,
	)
}

func cvBuildLeafMaterialV2Mode(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	validateEvidence bool,
) (*cvLeafV2, []byte, error) {
	if context == nil || coreProof == nil || partition == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) {
		return nil, nil, fmt.Errorf("invalid CV V2 leaf input")
	}
	if err := cvValidateEvidencePartitionV2(context, partition); err != nil {
		return nil, nil, err
	}
	if err := cvValidateReceiverMaterialForLeafV2(context, receivers); err != nil {
		return nil, nil, err
	}
	if err := cvValidateValidatorMaterialForLeafV2(context, validators); err != nil {
		return nil, nil, err
	}
	leaf := &cvLeafV2{
		Context: *cvCloneLeafContextV2(context), DealerID: dealerID,
		CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...), CoreProof: cvCloneCoreProofV2(coreProof),
		Receivers: make([]cvLeafReceiverV2, len(offers)),
		Partition: cvEvidencePartitionV2{
			ACKReceiverIndices:      append([]int(nil), partition.ACKReceiverIndices...),
			FallbackReceiverIndices: append([]int(nil), partition.FallbackReceiverIndices...),
		},
	}
	for i := range offers {
		if offers[i] == nil {
			return nil, nil, fmt.Errorf("CV V2 leaf is missing receiver offer")
		}
		leaf.Receivers[i].Offer = *cvCloneReceiverLaneOfferV2(offers[i])
		if acks[i] != nil {
			leaf.Receivers[i].ACK = &cvACKEvidenceV2{
				Ownership: cvCloneOwnershipProofV2(&acks[i].Ownership), Signature: append([]byte(nil), acks[i].Signature...),
			}
		}
	}
	if fallback != nil {
		if validateEvidence {
			fallbackWire, err := cvFallbackEvidenceV2CanonicalBytes(fallback, context)
			if err != nil {
				return nil, nil, err
			}
			leaf.Fallback, err = cvDecodeFallbackEvidenceV2(fallbackWire, context)
			if err != nil {
				return nil, nil, err
			}
		} else {
			leaf.Fallback = cvCloneFallbackEvidenceV2(fallback)
			if leaf.Fallback == nil {
				return nil, nil, fmt.Errorf("invalid verified CV V2 fallback evidence")
			}
		}
	}
	if validateEvidence {
		if err := cvVerifyLeafStatementV2(leaf, context, receivers); err != nil {
			return nil, nil, err
		}
	}
	secret, ok := validators.localSecrets[dealerID]
	if !ok {
		return nil, nil, fmt.Errorf("missing local CV V2 dealer signing secret")
	}
	unsigned, err := cvLeafV2UnsignedCanonicalBytesAfterValidation(leaf, receivers)
	if err != nil {
		return nil, nil, err
	}
	statement := hashBytes([]byte(cvDealerSignatureDomainV2), unsigned)
	leaf.DealerSignature, err = cvSignValidatorV2(secret, cvDealerSignatureDomainV2, statement)
	if err != nil {
		return nil, nil, err
	}
	wire, err := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		return nil, nil, err
	}
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainV2), wire)
	return leaf, wire, nil
}

func cvCloneFallbackEvidenceV2(evidence *cvFallbackEvidenceV2) *cvFallbackEvidenceV2 {
	if evidence == nil || evidence.Range.proof == nil {
		return nil
	}
	out := &cvFallbackEvidenceV2{
		ReceiverIndices: append([]int(nil), evidence.ReceiverIndices...),
		Link: cvFallbackLinkProofV2{
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
	out.Range = cvFallbackRangeProofV2{backend: evidence.Range.backend, proof: &compact}
	return out
}

// cvVerifyAPVSSV2 is the unique verifier for both ACK and fallback evidence.
func cvVerifyAPVSSV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) error {
	return cvVerifyAPVSSModeV2(leaf, expectedContext, receivers, validators, true)
}

func cvVerifyAPVSSAfterPointDecodingV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) error {
	return cvVerifyAPVSSModeV2(leaf, expectedContext, receivers, validators, false)
}

func cvVerifyAPVSSModeV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	validatePoints bool,
) error {
	if leaf == nil {
		return fmt.Errorf("nil CV V2 leaf")
	}
	var statementErr error
	if validatePoints {
		statementErr = cvVerifyLeafStatementV2(leaf, expectedContext, receivers)
	} else {
		statementErr = cvVerifyLeafStatementAfterPointDecodingV2(leaf, expectedContext, receivers)
	}
	if statementErr != nil {
		return statementErr
	}
	if err := cvValidateValidatorMaterialForLeafV2(expectedContext, validators); err != nil {
		return err
	}
	dealerIndex, ok := validators.memberIndex[leaf.DealerID]
	if !ok {
		return fmt.Errorf("CV V2 dealer is outside validator registry")
	}
	statement := leaf.decodeVerifiedStatement
	if statement == nil {
		unsigned, err := cvLeafV2UnsignedCanonicalBytesAfterValidation(leaf, receivers)
		if err != nil {
			return err
		}
		statement = hashBytes([]byte(cvDealerSignatureDomainV2), unsigned)
	}
	if !cvVerifyValidatorSignatureV2(
		&validators.publicKeys[dealerIndex], cvDealerSignatureDomainV2, statement, leaf.DealerSignature,
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
	wire, err := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		return err
	}
	expectedDigest := hashBytes([]byte(cvLeafDigestDomainV2), wire)
	if len(leaf.Digest) != 32 || !bytes.Equal(leaf.Digest, expectedDigest) {
		return fmt.Errorf("invalid CV V2 leaf digest")
	}
	return nil
}

func cvVerifyLeafStatementV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
) error {
	return cvVerifyLeafStatementModeV2(leaf, expectedContext, receivers, true)
}

func cvVerifyLeafStatementAfterPointDecodingV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
) error {
	return cvVerifyLeafStatementModeV2(leaf, expectedContext, receivers, false)
}

func cvVerifyReceiverEvaluationsExactV2(
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

func cvVerifyReceiverEvaluationsBatchV2(
	context *cvLeafContextV2, dealerID int, commitments, evaluations []bls12381.G1Affine,
	validatePoints bool,
) error {
	if context == nil || dealerID < 0 || len(commitments) == 0 || len(evaluations) != len(context.NewRoster) {
		return fmt.Errorf("invalid CV V2 receiver evaluation batch")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
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
	challenge, err := cvHashToFr(cvLeafEvaluationBatchV2, statement.Bytes())
	if err != nil {
		return err
	}
	if challenge.IsZero() {
		challenge, err = cvHashToFr(cvLeafEvaluationBatchV2, statement.Bytes(), []byte("nonzero"))
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
	if err := cvVerifyReceiverEvaluationsExactV2(commitments, evaluations); err != nil {
		return err
	}
	return fmt.Errorf("CV V2 receiver evaluation batch mismatch")
}

func cvVerifyOwnershipBatchV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, validatePoints bool,
) error {
	if context == nil || dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) {
		return fmt.Errorf("invalid CV V2 ownership batch")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return err
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
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
			shapeErr = cvValidateLaneOfferShapeV2(context, offer, &receiverPublicKeys[i])
		} else {
			shapeErr = cvValidateLaneOfferShapeAfterPointDecodingV2(context, offer, &receiverPublicKeys[i])
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
		ownershipChallenges[i], err = cvOwnershipChallengeScalarAfterValidationV2(
			context, dealerID, offer, &receiverPublicKeys[i], proof,
		)
		if err != nil {
			return err
		}
		cvWritePoint(&statement, &receiverPublicKeys[i])
		offerWire, wireErr := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealerID, offer)
		if wireErr != nil {
			return wireErr
		}
		_ = cvWriteBytes(&statement, offerWire)
	}
	batchChallenge, err := cvHashToFr(cvLeafOwnershipBatchV2, statement.Bytes())
	if err != nil {
		return err
	}
	if batchChallenge.IsZero() {
		batchChallenge, err = cvHashToFr(cvLeafOwnershipBatchV2, statement.Bytes(), []byte("nonzero"))
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
		weightedResponse, weightedErr := cvWeightedScalarV2(
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
		if err := cvVerifyOwnershipModeV2(
			context, dealerID, offer, &receiverPublicKeys[i], validatePoints,
		); err != nil {
			return fmt.Errorf("invalid CV V2 ownership batch receiver %d: %w", offer.ReceiverIndex, err)
		}
	}
	return fmt.Errorf("CV V2 ownership batch mismatch")
}

func cvVerifyLeafStatementModeV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
	validatePoints bool,
) error {
	if leaf == nil || expectedContext == nil || leaf.DealerID < 0 ||
		len(leaf.CoefficientCommitments) != expectedContext.SharingDegree+1 ||
		len(leaf.Receivers) != len(expectedContext.NewRoster) ||
		cvValidateReceiverMaterialForLeafV2(expectedContext, receivers) != nil {
		return fmt.Errorf("invalid CV V2 leaf statement")
	}
	expectedContextWire, err := cvLeafContextV2CanonicalBytes(expectedContext)
	if err != nil {
		return err
	}
	actualContextWire, err := cvLeafContextV2CanonicalBytes(&leaf.Context)
	if err != nil || !bytes.Equal(actualContextWire, expectedContextWire) {
		return fmt.Errorf("CV V2 leaf context mismatch")
	}
	if !cvMemberInRosterV2(leaf.DealerID, expectedContext.OldRoster) {
		return fmt.Errorf("CV V2 leaf dealer is outside old roster")
	}
	var coreErr error
	if validatePoints {
		coreErr = cvVerifyCoreV2(expectedContext, leaf.DealerID, leaf.CoefficientCommitments, &leaf.CoreProof)
	} else {
		coreErr = cvVerifyCoreAfterPointDecodingV2(
			expectedContext, leaf.DealerID, leaf.CoefficientCommitments, &leaf.CoreProof,
		)
	}
	if coreErr != nil {
		return coreErr
	}
	if err := cvValidateEvidencePartitionV2(expectedContext, &leaf.Partition); err != nil {
		return err
	}
	fallbackSet := make(map[int]struct{}, len(leaf.Partition.FallbackReceiverIndices))
	for _, index := range leaf.Partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	fallbackOffers := make([]*cvReceiverLaneOfferV2, 0, len(fallbackSet))
	fallbackKeys := make([]bls12381.G1Affine, 0, len(fallbackSet))
	ackOffers := make([]*cvReceiverLaneOfferV2, 0, len(leaf.Receivers)-len(fallbackSet))
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
	if err := cvVerifyReceiverEvaluationsBatchV2(
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
		if err := cvVerifyOwnershipBatchV2(
			expectedContext, leaf.DealerID, ackOffers, ackKeys, validatePoints,
		); err != nil {
			return err
		}
	}
	for _, i := range ackReceiverIndices {
		receiver := &leaf.Receivers[i]
		if err := cvVerifyACKAfterLocalOwnershipValidationV2(
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
			fallbackErr = cvVerifyFallbackEvidenceV2(
				expectedContext, leaf.DealerID, fallbackOffers, fallbackKeys, leaf.Fallback,
			)
		} else {
			fallbackErr = cvVerifyFallbackEvidenceAfterPointDecodingV2(
				expectedContext, leaf.DealerID, fallbackOffers, fallbackKeys, leaf.Fallback,
			)
		}
		if fallbackErr != nil {
			return fmt.Errorf("invalid CV V2 fallback evidence: %w", fallbackErr)
		}
	}
	return nil
}

func cvLeafV2UnsignedCanonicalBytes(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2,
) ([]byte, error) {
	return cvLeafV2UnsignedCanonicalBytesMode(leaf, receivers, true, 0)
}

func cvLeafV2UnsignedCanonicalBytesAfterValidation(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2,
) ([]byte, error) {
	return cvLeafV2UnsignedCanonicalBytesMode(leaf, receivers, false, 0)
}

// cvLeafV2UnsignedCanonicalBytesSized preallocates the assembly buffer when the
// caller already knows the exact canonical length (the decode path compares
// against a wire of that size). The hint never changes output bytes; an
// under-estimate simply falls back to incremental growth.
func cvLeafV2UnsignedCanonicalBytesSized(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, sizeHint int,
) ([]byte, error) {
	return cvLeafV2UnsignedCanonicalBytesMode(leaf, receivers, false, sizeHint)
}

func cvLeafV2UnsignedCanonicalBytesMode(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validateEvidence bool, sizeHint int,
) ([]byte, error) {
	if leaf == nil || cvValidateReceiverMaterialForLeafV2(&leaf.Context, receivers) != nil ||
		cvValidateEvidencePartitionV2(&leaf.Context, &leaf.Partition) != nil ||
		len(leaf.Receivers) != len(leaf.Context.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(&leaf.Context)
	if err != nil {
		return nil, err
	}
	var coreWire []byte
	if validateEvidence {
		coreWire, err = cvCoreProofV2CanonicalBytes(&leaf.CoreProof, len(leaf.CoefficientCommitments))
	} else {
		coreWire, err = cvCoreProofV2CanonicalBytesAfterValidation(&leaf.CoreProof, len(leaf.CoefficientCommitments))
	}
	if err != nil {
		return nil, err
	}
	partitionWire, err := cvEvidencePartitionV2CanonicalBytes(&leaf.Context, &leaf.Partition)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if sizeHint > 0 {
		wire.Grow(sizeHint)
	}
	_ = cvWriteBytes(&wire, []byte(cvLeafUnsignedWireDomainV2))
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
				offerWire, err = cvFallbackLaneOfferV2CanonicalBytes(
					&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
				)
			} else {
				offerWire, err = cvFallbackLaneOfferV2CanonicalBytesAfterValidation(
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
				offerWire, err = cvReceiverLaneOfferV2CanonicalBytes(
					&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
				)
			} else {
				offerWire, err = cvReceiverLaneOfferV2CanonicalBytesAfterValidation(
					&leaf.Context, leaf.DealerID, &receiver.Offer,
				)
			}
			if err != nil {
				return nil, err
			}
			if validateEvidence {
				ackWire, err = cvACKEvidenceV2CanonicalBytes(receiver.ACK, &leaf.Context)
			} else {
				ackWire, err = cvACKEvidenceV2CanonicalBytesAfterValidation(receiver.ACK, &leaf.Context)
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
			fallbackWire, err = cvFallbackEvidenceV2CanonicalBytes(leaf.Fallback, &leaf.Context)
		} else {
			fallbackWire, err = cvFallbackEvidenceV2CanonicalBytesAfterValidation(leaf.Fallback, &leaf.Context)
		}
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&wire, fallbackWire)
	}
	return wire.Bytes(), nil
}

func cvLeafV2CanonicalBytes(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) ([]byte, error) {
	return cvLeafV2CanonicalBytesMode(leaf, receivers, validators, true, 0)
}

func cvLeafV2CanonicalBytesAfterValidation(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) ([]byte, error) {
	return cvLeafV2CanonicalBytesMode(leaf, receivers, validators, false, 0)
}

// cvLeafV2CanonicalBytesSized is the decode-path variant: the caller knows the
// wire length the canonical encoding must reproduce, so both assembly buffers
// are allocated once instead of doubling through megabytes per leaf.
func cvLeafV2CanonicalBytesSized(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	sizeHint int,
) ([]byte, error) {
	return cvLeafV2CanonicalBytesMode(leaf, receivers, validators, false, sizeHint)
}

func cvLeafV2CanonicalBytesMode(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	validateEvidence bool, sizeHint int,
) ([]byte, error) {
	if leaf == nil || len(leaf.DealerSignature) != bls12381.SizeOfG1AffineCompressed ||
		cvValidateValidatorMaterialForLeafV2(&leaf.Context, validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf wire")
	}
	var unsigned []byte
	var err error
	unsignedHint := 0
	if sizeHint > 64 {
		unsignedHint = sizeHint - 64
	}
	if validateEvidence {
		unsigned, err = cvLeafV2UnsignedCanonicalBytes(leaf, receivers)
	} else {
		unsigned, err = cvLeafV2UnsignedCanonicalBytesSized(leaf, receivers, unsignedHint)
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if sizeHint > 0 {
		wire.Grow(sizeHint)
	}
	_ = cvWriteBytes(&wire, []byte(cvLeafWireDomainV2))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, leaf.DealerSignature)
	return wire.Bytes(), nil
}

func cvDecodeLeafV2(
	wire []byte, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	return cvDecodeLeafV2Sidechannel(wire, nil, expectedContext, receivers, validators)
}

// cvDecodeLeafV2WithHints decodes with an optional uncompressed-point
// attachment. Hints only change how y-coordinates are obtained; every
// accepted point still recompresses to the exact signed wire bytes.
func cvDecodeLeafV2WithHints(
	wire, hints []byte, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	return cvDecodeLeafV2Sidechannel(
		wire, newCVDecodeSidechannelHintsV2(hints), expectedContext, receivers, validators,
	)
}

// cvRecordLeafDeferredHintsV2 decodes exactly as consumers will and records
// the uncompressed form of every deferred point in wire order. A nil result
// means the decode rejected the wire, so no attachment is served.
func cvRecordLeafDeferredHintsV2(
	wire []byte, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) []byte {
	side := newCVDecodeSidechannelRecordingV2()
	if _, err := cvDecodeLeafV2Sidechannel(wire, side, expectedContext, receivers, validators); err != nil {
		return nil
	}
	return side.record
}

func cvDecodeLeafV2Sidechannel(
	wire []byte, side *cvDecodeSidechannelV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	// A leaf decode always owns a sidechannel: with no hints it exists purely
	// to collect every deferred point for one leaf-wide subgroup batch.
	if side == nil {
		side = &cvDecodeSidechannelV2{collectSubgroup: true}
	} else {
		side.collectSubgroup = true
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLeafWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafWireDomainV2)) {
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
	leaf, err := cvDecodeLeafV2UnsignedSidechannel(unsigned, side, expectedContext, receivers)
	if err != nil {
		return nil, err
	}
	// One leaf-wide subgroup batch replaces the per-section checks; the leaf
	// is rejected here before any structure escapes to the caller.
	if err := side.finishDeferredSubgroupBatch(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf point: %w", err)
	}
	leaf.DealerSignature = signature
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainV2), wire)
	// The unsigned statement hashes the exact canonical sub-slice of the wire
	// that framing already delimitated, so the APVSS verifier can reuse it
	// instead of re-encoding the full leaf again.
	// Wire framing is [len domain][domain][len unsigned][unsigned][len
	// signature][signature]; hash the exact unsigned span instead of
	// re-encoding the whole leaf again for the dealer-signature statement.
	unsignedOffset := 4 + len(cvLeafWireDomainV2) + 4
	unsignedWire := wire[unsignedOffset : unsignedOffset+len(unsigned)]
	leaf.decodeVerifiedStatement = hashBytes([]byte(cvDealerSignatureDomainV2), unsignedWire)
	canonical, err := cvLeafV2CanonicalBytesSized(leaf, receivers, validators, len(wire))
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 leaf")
	}
	leaf.decodeCanonicalVerified = true
	if err := cvVerifyAPVSSAfterPointDecodingV2(leaf, expectedContext, receivers, validators); err != nil {
		return nil, err
	}
	return leaf, nil
}

func cvDecodeLeafV2Unsigned(
	wire []byte, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
) (*cvLeafV2, error) {
	return cvDecodeLeafV2UnsignedSidechannel(wire, nil, expectedContext, receivers)
}

func cvDecodeLeafV2UnsignedSidechannel(
	wire []byte, side *cvDecodeSidechannelV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2,
) (*cvLeafV2, error) {
	if cvValidateReceiverMaterialForLeafV2(expectedContext, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf receiver registry")
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvLeafUnsignedWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafUnsignedWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf domain")
	}
	contextWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	context, err := cvDecodeLeafContextV2(contextWire)
	if err != nil {
		return nil, err
	}
	expectedWire, err := cvLeafContextV2CanonicalBytes(expectedContext)
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
	coreProof, err := cvDecodeCoreProofV2Sidechannel(coreWire, len(commitments), side)
	if err != nil {
		return nil, err
	}
	partitionWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	partition, err := cvDecodeEvidencePartitionV2(partitionWire, expectedContext)
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != len(expectedContext.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 receiver transcript count")
	}
	leaf := &cvLeafV2{
		Context: *context, DealerID: int(dealer), CoefficientCommitments: commitments,
		CoreProof: *coreProof, Partition: *partition, Receivers: make([]cvLeafReceiverV2, count),
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
		var offer *cvReceiverLaneOfferV2
		if isFallback {
			offer, err = cvDecodeFallbackLaneOfferV2(
				offerWire, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
				&receivers.encryptionPublicKeys[i],
			)
		} else {
			offer, err = cvDecodeReceiverLaneOfferBeforeVerificationV2Sidechannel(
				offerWire, side, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
				&receivers.encryptionPublicKeys[i],
			)
		}
		if err != nil {
			return nil, err
		}
		leaf.Receivers[i] = cvLeafReceiverV2{Offer: *offer}
		if !isFallback {
			ackWire, readErr := r.bytes(cvMaxLeafProofWireBytes)
			if readErr != nil {
				return nil, readErr
			}
			ack, readErr := cvDecodeACKEvidenceV2Sidechannel(ackWire, side, expectedContext)
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
		leaf.Fallback, err = cvDecodeFallbackEvidenceV2(fallbackWire, expectedContext)
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
	canonical, err := cvLeafV2UnsignedCanonicalBytesAfterValidation(leaf, receivers)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 unsigned leaf")
	}
	return leaf, nil
}

func cvValidateReceiverMaterialForLeafV2(
	context *cvLeafContextV2, material *cvReceiverKeyMaterialV2,
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

func cvValidateValidatorMaterialForLeafV2(
	context *cvLeafContextV2, material *cvValidatorKeyMaterialV2,
) error {
	if context == nil || material == nil || material.sid != context.SID || material.epoch != context.Epoch ||
		!equalInts(material.memberOrder, context.OldRoster) ||
		len(material.publicKeys) != len(context.OldRoster) {
		return fmt.Errorf("CV V2 validator registry does not match leaf context")
	}
	return nil
}

func cvCloneLeafContextV2(context *cvLeafContextV2) *cvLeafContextV2 {
	if context == nil {
		return nil
	}
	cloned := *context
	cloned.OldRoster = append([]int(nil), context.OldRoster...)
	cloned.NewRoster = append([]int(nil), context.NewRoster...)
	cloned.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	return &cloned
}

func cvCloneCoreProofV2(proof *cvCoreProofV2) cvCoreProofV2 {
	if proof == nil {
		return cvCoreProofV2{}
	}
	return cvCoreProofV2{
		NonceCommitments:  append([]bls12381.G1Affine(nil), proof.NonceCommitments...),
		ScalarResponses:   append([]fr.Element(nil), proof.ScalarResponses...),
		BlindingResponses: append([]fr.Element(nil), proof.BlindingResponses...),
	}
}

func cvCloneReceiverLaneOfferV2(offer *cvReceiverLaneOfferV2) *cvReceiverLaneOfferV2 {
	if offer == nil {
		return nil
	}
	cloned := *offer
	cloned.ScalarChunks = append([]cvElGamalCiphertext(nil), offer.ScalarChunks...)
	cloned.Blinding = offer.Blinding
	cloned.Ownership = cvCloneOwnershipProofV2(&offer.Ownership)
	return &cloned
}
