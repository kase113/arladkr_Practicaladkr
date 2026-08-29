package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvFallbackLinkWireDomainV2      = "ARL-CV-sAPVSS/v2-scalar-group/fallback-link"
	cvFallbackLinkChallengeDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/fallback-link/challenge"
)

type cvFallbackLinkProofV2 struct {
	DigitCommitments          []bls12381.G1Affine
	DigitOpeningCommitments   []bls12381.G1Affine
	ScalarCoinCommitments     []bls12381.G1Affine
	ScalarCipherCommitments   []bls12381.G1Affine
	BlindingCoinCommitments   []bls12381.G1Affine
	BlindingCipherCommitments []bls12381.G1Affine
	EvaluationCommitments     []bls12381.G1Affine
	DigitResponses            []fr.Element
	DigitBlindResponses       []fr.Element
	ScalarCoinResponses       []fr.Element
	BlindingCoinResponses     []fr.Element
	BlindingShareResponses    []fr.Element
}

// cvFallbackDigitWitnessV2 stays local and supplies the exact Pedersen
// blindings consumed by the aggregated scalar-digit range proof.
type cvFallbackDigitWitnessV2 struct {
	Blindings []fr.Element
}

func cvProveFallbackLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, witnesses []*cvDealerReceiverWitnessV2,
) (*cvFallbackLinkProofV2, *cvFallbackDigitWitnessV2, error) {
	chunks, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || len(witnesses) != len(offers) {
		return nil, nil, fmt.Errorf("invalid CV V2 fallback-link witness")
	}
	receivers := len(offers)
	proof := &cvFallbackLinkProofV2{
		DigitCommitments:          make([]bls12381.G1Affine, total),
		DigitOpeningCommitments:   make([]bls12381.G1Affine, total),
		ScalarCoinCommitments:     make([]bls12381.G1Affine, total),
		ScalarCipherCommitments:   make([]bls12381.G1Affine, total),
		BlindingCoinCommitments:   make([]bls12381.G1Affine, receivers),
		BlindingCipherCommitments: make([]bls12381.G1Affine, receivers),
		EvaluationCommitments:     make([]bls12381.G1Affine, receivers),
		DigitResponses:            make([]fr.Element, total), DigitBlindResponses: make([]fr.Element, total),
		ScalarCoinResponses:    make([]fr.Element, total),
		BlindingCoinResponses:  make([]fr.Element, receivers),
		BlindingShareResponses: make([]fr.Element, receivers),
	}
	local := &cvFallbackDigitWitnessV2{Blindings: make([]fr.Element, total)}
	digitNonces := make([]fr.Element, total)
	digitBlindNonces := make([]fr.Element, total)
	scalarCoinNonces := make([]fr.Element, total)
	blindingCoinNonces := make([]fr.Element, receivers)
	blindingShareNonces := make([]fr.Element, receivers)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	for receiver, witness := range witnesses {
		if witness == nil || len(witness.ScalarDigits) != chunks || len(witness.ScalarCoins) != chunks {
			return nil, nil, fmt.Errorf("invalid CV V2 fallback-link witness dimensions")
		}
		for chunk := 0; chunk < chunks; chunk++ {
			position := cvFallbackLinkPositionV2(receiver, chunk, chunks)
			for _, nonce := range []*fr.Element{
				&local.Blindings[position], &digitNonces[position],
				&digitBlindNonces[position], &scalarCoinNonces[position],
			} {
				if _, err := nonce.SetRandom(); err != nil {
					return nil, nil, err
				}
			}
			var digit fr.Element
			digit.SetUint64(witness.ScalarDigits[chunk])
			proof.DigitCommitments[position] = cvPointBaseAndTimes(
				&digit, &h, &local.Blindings[position],
			)
			proof.DigitOpeningCommitments[position] = cvPointBaseAndTimes(
				&digitNonces[position], &h, &digitBlindNonces[position],
			)
			proof.ScalarCoinCommitments[position] = cvPointTimes(&genG1, &scalarCoinNonces[position])
			proof.ScalarCipherCommitments[position] = cvPointBaseAndTimes(
				&digitNonces[position], &receiverPublicKeys[receiver], &scalarCoinNonces[position],
			)
		}
		if _, err := blindingCoinNonces[receiver].SetRandom(); err != nil {
			return nil, nil, err
		}
		if _, err := blindingShareNonces[receiver].SetRandom(); err != nil {
			return nil, nil, err
		}
		proof.BlindingCoinCommitments[receiver] = cvPointTimes(&genG1, &blindingCoinNonces[receiver])
		proof.BlindingCipherCommitments[receiver] = cvPointJointTimes(
			&receiverPublicKeys[receiver], &blindingCoinNonces[receiver], &h, &blindingShareNonces[receiver],
		)
		weighted, err := cvFallbackWeightedNoncesV2(receiver, chunks, context.Profile.chunkBits, digitNonces)
		if err != nil {
			return nil, nil, err
		}
		proof.EvaluationCommitments[receiver] = cvPointBaseAndTimes(
			&weighted, &h, &blindingShareNonces[receiver],
		)
	}
	challenge, err := cvFallbackLinkChallengeAfterValidationV2(
		context, dealerID, offers, receiverPublicKeys, proof,
	)
	if err != nil {
		return nil, nil, err
	}
	for receiver, witness := range witnesses {
		for chunk := 0; chunk < chunks; chunk++ {
			position := cvFallbackLinkPositionV2(receiver, chunk, chunks)
			var digit fr.Element
			digit.SetUint64(witness.ScalarDigits[chunk])
			proof.DigitResponses[position].Mul(&challenge, &digit).Add(&proof.DigitResponses[position], &digitNonces[position])
			proof.DigitBlindResponses[position].Mul(&challenge, &local.Blindings[position]).Add(&proof.DigitBlindResponses[position], &digitBlindNonces[position])
			proof.ScalarCoinResponses[position].Mul(&challenge, &witness.ScalarCoins[chunk]).Add(&proof.ScalarCoinResponses[position], &scalarCoinNonces[position])
		}
		proof.BlindingCoinResponses[receiver].Mul(&challenge, &witness.BlindingCoin).Add(&proof.BlindingCoinResponses[receiver], &blindingCoinNonces[receiver])
		proof.BlindingShareResponses[receiver].Mul(&challenge, &witness.Blinding).Add(&proof.BlindingShareResponses[receiver], &blindingShareNonces[receiver])
	}
	return proof, local, nil
}

func cvVerifyFallbackLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) error {
	return cvVerifyFallbackLinkModeV2(context, dealerID, offers, receiverPublicKeys, proof, true)
}

func cvVerifyFallbackLinkAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) error {
	return cvVerifyFallbackLinkModeV2(context, dealerID, offers, receiverPublicKeys, proof, false)
}

func cvVerifyFallbackLinkModeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2, validatePoints bool,
) error {
	var chunks, total int
	var err error
	if validatePoints {
		chunks, total, err = cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	} else {
		chunks, total, err = cvValidateFallbackLinkStatementAfterPointDecodingV2(
			context, dealerID, offers, receiverPublicKeys,
		)
	}
	if err != nil || !cvValidFallbackLinkProofShapeModeV2(proof, total, len(offers), validatePoints) {
		return fmt.Errorf("invalid CV V2 fallback-link proof")
	}
	challenge, err := cvFallbackLinkChallengeAfterValidationV2(
		context, dealerID, offers, receiverPublicKeys, proof,
	)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	for receiver, offer := range offers {
		for chunk := 0; chunk < chunks; chunk++ {
			position := cvFallbackLinkPositionV2(receiver, chunk, chunks)
			ciphertext := &offer.ScalarChunks[chunk]
			left := cvPointBaseAndTimes(
				&proof.DigitResponses[position], &h, &proof.DigitBlindResponses[position],
			)
			right := cvPointSum(&proof.DigitOpeningCommitments[position],
				pointPtr(cvPointTimes(&proof.DigitCommitments[position], &challenge)))
			if !left.Equal(&right) {
				return fmt.Errorf("invalid CV V2 fallback digit-commitment equation")
			}
			left = cvPointTimes(&genG1, &proof.ScalarCoinResponses[position])
			right = cvPointSum(&proof.ScalarCoinCommitments[position],
				pointPtr(cvPointTimes(&ciphertext.r, &challenge)))
			if !left.Equal(&right) {
				return fmt.Errorf("invalid CV V2 fallback scalar coin equation")
			}
			left = cvPointBaseAndTimes(
				&proof.DigitResponses[position], &receiverPublicKeys[receiver], &proof.ScalarCoinResponses[position],
			)
			right = cvPointSum(&proof.ScalarCipherCommitments[position],
				pointPtr(cvPointTimes(&ciphertext.c, &challenge)))
			if !left.Equal(&right) {
				return fmt.Errorf("invalid CV V2 fallback scalar ciphertext equation")
			}
		}
		leftBlindingCoin := cvPointTimes(&genG1, &proof.BlindingCoinResponses[receiver])
		rightBlindingCoin := cvPointSum(&proof.BlindingCoinCommitments[receiver],
			pointPtr(cvPointTimes(&offer.Blinding.r, &challenge)))
		if !leftBlindingCoin.Equal(&rightBlindingCoin) {
			return fmt.Errorf("invalid CV V2 fallback blinding coin equation")
		}
		leftBlindingCipher := cvPointJointTimes(
			&receiverPublicKeys[receiver], &proof.BlindingCoinResponses[receiver],
			&h, &proof.BlindingShareResponses[receiver],
		)
		rightBlindingCipher := cvPointSum(&proof.BlindingCipherCommitments[receiver],
			pointPtr(cvPointTimes(&offer.Blinding.c, &challenge)))
		if !leftBlindingCipher.Equal(&rightBlindingCipher) {
			return fmt.Errorf("invalid CV V2 fallback blinding ciphertext equation")
		}
		responses := proof.DigitResponses[receiver*chunks : (receiver+1)*chunks]
		weighted, err := cvWeightedScalarV2(responses, context.Profile.chunkBits)
		if err != nil {
			return err
		}
		leftEvaluation := cvPointBaseAndTimes(
			&weighted, &h, &proof.BlindingShareResponses[receiver],
		)
		rightEvaluation := cvPointSum(&proof.EvaluationCommitments[receiver],
			pointPtr(cvPointTimes(&offer.Evaluation, &challenge)))
		if !leftEvaluation.Equal(&rightEvaluation) {
			return fmt.Errorf("invalid CV V2 fallback evaluation equation")
		}
	}
	return nil
}

func cvValidateFallbackLinkStatementAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine,
) (int, int, error) {
	if err := cvValidateLeafContextV2(context); err != nil || dealerID < 0 ||
		!cvMemberInRosterV2(dealerID, context.OldRoster) || len(offers) == 0 ||
		len(offers) != len(receiverPublicKeys) || len(offers) > cvNewFaultBoundFromContextV2(context) {
		return 0, 0, fmt.Errorf("invalid decoded CV V2 fallback-link statement")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return 0, 0, err
	}
	previous := 0
	for i, offer := range offers {
		if offer == nil || receiverPublicKeys[i].IsInfinity() || offer.ReceiverIndex <= previous ||
			cvValidateLaneOfferShapeAfterPointDecodingV2(context, offer, &receiverPublicKeys[i]) != nil {
			return 0, 0, fmt.Errorf("invalid decoded CV V2 fallback-link receiver order")
		}
		previous = offer.ReceiverIndex
	}
	return chunks, len(offers) * chunks, nil
}

func cvFallbackLinkChallengeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) (fr.Element, error) {
	_, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || !cvValidFallbackLinkProofShapeV2(proof, total, len(offers)) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 fallback-link challenge")
	}
	return cvFallbackLinkChallengeModeV2(context, dealerID, offers, receiverPublicKeys, proof, true)
}

func cvFallbackLinkChallengeAfterValidationV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) (fr.Element, error) {
	if context == nil || dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) || proof == nil {
		return fr.Element{}, fmt.Errorf("invalid verified CV V2 fallback-link challenge")
	}
	return cvFallbackLinkChallengeModeV2(context, dealerID, offers, receiverPublicKeys, proof, false)
}

func cvFallbackLinkChallengeModeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2, validatePoints bool,
) (fr.Element, error) {
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return fr.Element{}, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(dealerID))
	_ = cvWriteUint32(&wire, len(offers))
	for i, offer := range offers {
		cvWriteUint64(&wire, uint64(offer.ReceiverID))
		cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
		cvWritePoint(&wire, &receiverPublicKeys[i])
		cvWritePoint(&wire, &offer.Evaluation)
		_ = cvWriteUint32(&wire, len(offer.ScalarChunks))
		for chunk := range offer.ScalarChunks {
			cvWriteCiphertext(&wire, &offer.ScalarChunks[chunk])
		}
		cvWriteCiphertext(&wire, &offer.Blinding)
	}
	for _, points := range cvFallbackLinkPointVectorsV2(proof) {
		if err := cvWritePointVectorMode(&wire, points, validatePoints); err != nil {
			return fr.Element{}, err
		}
	}
	return cvHashToFr(cvFallbackLinkChallengeDomainV2, wire.Bytes())
}

func cvValidateFallbackLinkStatementV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine,
) (int, int, error) {
	if err := cvValidateLeafContextV2(context); err != nil || dealerID < 0 ||
		!cvMemberInRosterV2(dealerID, context.OldRoster) || len(offers) == 0 ||
		len(offers) != len(receiverPublicKeys) || len(offers) > cvNewFaultBoundFromContextV2(context) {
		return 0, 0, fmt.Errorf("invalid CV V2 fallback-link statement")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return 0, 0, err
	}
	previous := 0
	for i, offer := range offers {
		if offer == nil || offer.ReceiverIndex <= previous ||
			cvValidateLaneOfferShapeV2(context, offer, &receiverPublicKeys[i]) != nil {
			return 0, 0, fmt.Errorf("invalid CV V2 fallback-link receiver order")
		}
		previous = offer.ReceiverIndex
	}
	return chunks, len(offers) * chunks, nil
}

func cvFallbackWeightedNoncesV2(receiver, chunks int, chunkBits uint, nonces []fr.Element) (fr.Element, error) {
	start := receiver * chunks
	if receiver < 0 || chunks <= 0 || start+chunks > len(nonces) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 fallback nonce dimensions")
	}
	return cvWeightedScalarV2(nonces[start:start+chunks], chunkBits)
}

func cvFallbackLinkPositionV2(receiver, chunk, chunks int) int {
	return receiver*chunks + chunk
}

func cvFallbackLinkPointVectorsV2(proof *cvFallbackLinkProofV2) [][]bls12381.G1Affine {
	return [][]bls12381.G1Affine{
		proof.DigitCommitments, proof.DigitOpeningCommitments,
		proof.ScalarCoinCommitments, proof.ScalarCipherCommitments,
		proof.BlindingCoinCommitments, proof.BlindingCipherCommitments, proof.EvaluationCommitments,
	}
}

func cvValidFallbackLinkProofShapeV2(proof *cvFallbackLinkProofV2, total, receivers int) bool {
	return cvValidFallbackLinkProofShapeModeV2(proof, total, receivers, true)
}

func cvValidFallbackLinkProofShapeAfterValidationV2(proof *cvFallbackLinkProofV2, total, receivers int) bool {
	return cvValidFallbackLinkProofShapeModeV2(proof, total, receivers, false)
}

func cvValidFallbackLinkProofShapeModeV2(
	proof *cvFallbackLinkProofV2, total, receivers int, validatePoints bool,
) bool {
	if proof == nil || total <= 0 || receivers <= 0 || len(proof.DigitCommitments) != total ||
		len(proof.DigitOpeningCommitments) != total || len(proof.ScalarCoinCommitments) != total ||
		len(proof.ScalarCipherCommitments) != total || len(proof.BlindingCoinCommitments) != receivers ||
		len(proof.BlindingCipherCommitments) != receivers || len(proof.EvaluationCommitments) != receivers ||
		len(proof.DigitResponses) != total || len(proof.DigitBlindResponses) != total ||
		len(proof.ScalarCoinResponses) != total || len(proof.BlindingCoinResponses) != receivers ||
		len(proof.BlindingShareResponses) != receivers {
		return false
	}
	if validatePoints {
		for _, points := range cvFallbackLinkPointVectorsV2(proof) {
			for i := range points {
				if !cvValidG1(&points[i], true) {
					return false
				}
			}
		}
	}
	return true
}

func cvFallbackLinkProofV2CanonicalBytes(
	proof *cvFallbackLinkProofV2, context *cvLeafContextV2, fallbackCount int,
) ([]byte, error) {
	return cvFallbackLinkProofV2CanonicalBytesMode(proof, context, fallbackCount, true)
}

func cvFallbackLinkProofV2CanonicalBytesAfterValidation(
	proof *cvFallbackLinkProofV2, context *cvLeafContextV2, fallbackCount int,
) ([]byte, error) {
	return cvFallbackLinkProofV2CanonicalBytesMode(proof, context, fallbackCount, false)
}

func cvFallbackLinkProofV2CanonicalBytesMode(
	proof *cvFallbackLinkProofV2, context *cvLeafContextV2, fallbackCount int, validatePoints bool,
) ([]byte, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	total := fallbackCount * chunks
	if fallbackCount <= 0 || !cvValidFallbackLinkProofShapeModeV2(proof, total, fallbackCount, validatePoints) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackLinkWireDomainV2))
	for _, points := range cvFallbackLinkPointVectorsV2(proof) {
		if err := cvWritePointVectorMode(&wire, points, validatePoints); err != nil {
			return nil, err
		}
	}
	for _, scalars := range [][]fr.Element{
		proof.DigitResponses, proof.DigitBlindResponses, proof.ScalarCoinResponses,
		proof.BlindingCoinResponses, proof.BlindingShareResponses,
	} {
		if err := cvWriteScalarVector(&wire, scalars); err != nil {
			return nil, err
		}
	}
	return wire.Bytes(), nil
}

func cvDecodeFallbackLinkProofV2(
	wire []byte, context *cvLeafContextV2, fallbackCount int,
) (*cvFallbackLinkProofV2, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || fallbackCount <= 0 || fallbackCount > cvNewFaultBoundFromContextV2(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link decode parameters")
	}
	total := fallbackCount * chunks
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackLinkWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackLinkWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link domain")
	}
	pointCounts := []int{total, total, total, total, fallbackCount, fallbackCount, fallbackCount}
	points := make([][]bls12381.G1Affine, len(pointCounts))
	for i, count := range pointCounts {
		points[i], err = cvReadExactPointVector(r, count, "V2 fallback-link points")
		if err != nil {
			return nil, err
		}
	}
	scalarCounts := []int{total, total, total, fallbackCount, fallbackCount}
	scalars := make([][]fr.Element, len(scalarCounts))
	for i, count := range scalarCounts {
		scalars[i], err = cvReadExactScalarVectorV2(r, count)
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 fallback-link bytes")
	}
	proof := &cvFallbackLinkProofV2{
		DigitCommitments: points[0], DigitOpeningCommitments: points[1],
		ScalarCoinCommitments: points[2], ScalarCipherCommitments: points[3],
		BlindingCoinCommitments: points[4], BlindingCipherCommitments: points[5],
		EvaluationCommitments: points[6], DigitResponses: scalars[0], DigitBlindResponses: scalars[1],
		ScalarCoinResponses: scalars[2], BlindingCoinResponses: scalars[3], BlindingShareResponses: scalars[4],
	}
	canonical, err := cvFallbackLinkProofV2CanonicalBytesAfterValidation(proof, context, fallbackCount)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback-link proof")
	}
	return proof, nil
}
