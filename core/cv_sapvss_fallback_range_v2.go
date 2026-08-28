package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvFallbackRangeBackendV2         = "bulletproofs-bls12381-aggregated-v1"
	cvFallbackRangeWireDomainV2      = "ARL-CV-sAPVSS/v2-scalar-group/fallback-range"
	cvFallbackRangeStatementDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/fallback-range/statement"
)

// cvFallbackRangeProofV2 is a V2-domain adapter around the repository's
// standard aggregated Bulletproof implementation. It proves all flattened
// fallback digits against the exact commitments used by the link proof.
type cvFallbackRangeProofV2 struct {
	backend string
	proof   *apvssCompactRangeProof
}

func cvProveFallbackRangeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessV2,
	linkProof *cvFallbackLinkProofV2, linkWitness *cvFallbackDigitWitnessV2,
) (*cvFallbackRangeProofV2, error) {
	return cvProveFallbackRangeModeV2(
		context, dealerID, offers, receiverPublicKeys, dealerWitnesses, linkProof, linkWitness, true,
	)
}

func cvProveFallbackRangeAfterLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessV2,
	linkProof *cvFallbackLinkProofV2, linkWitness *cvFallbackDigitWitnessV2,
) (*cvFallbackRangeProofV2, error) {
	return cvProveFallbackRangeModeV2(
		context, dealerID, offers, receiverPublicKeys, dealerWitnesses, linkProof, linkWitness, false,
	)
}

func cvProveFallbackRangeModeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessV2,
	linkProof *cvFallbackLinkProofV2, linkWitness *cvFallbackDigitWitnessV2, validateLink bool,
) (*cvFallbackRangeProofV2, error) {
	var chunks, total int
	var err error
	if validateLink {
		chunks, total, err = cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	} else {
		chunks, total, err = cvValidateFallbackLinkStatementAfterPointDecodingV2(
			context, dealerID, offers, receiverPublicKeys,
		)
	}
	if err != nil || len(dealerWitnesses) != len(offers) || linkWitness == nil ||
		len(linkWitness.Blindings) != total ||
		(validateLink && !cvValidFallbackLinkProofShapeV2(linkProof, total, len(offers))) ||
		(!validateLink && !cvValidFallbackLinkProofShapeAfterValidationV2(linkProof, total, len(offers))) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range witness")
	}
	values := make([]uint64, total)
	for receiver := range offers {
		witness := dealerWitnesses[receiver]
		if witness == nil {
			return nil, fmt.Errorf("nil CV V2 fallback-range dealer witness")
		}
		if len(witness.ScalarDigits) != chunks {
			return nil, fmt.Errorf("invalid CV V2 fallback-range witness dimensions")
		}
		for chunk := 0; chunk < chunks; chunk++ {
			position := cvFallbackLinkPositionV2(receiver, chunk, chunks)
			values[position] = witness.ScalarDigits[chunk]
		}
	}
	var statement []byte
	if validateLink {
		statement, err = cvFallbackRangeStatementV2(context, dealerID, offers, receiverPublicKeys, linkProof)
	} else {
		statement, err = cvFallbackRangeStatementAfterValidationV2(
			context, dealerID, offers, receiverPublicKeys, linkProof,
		)
	}
	if err != nil {
		return nil, err
	}
	proof, err := apvssProveCompactRange(
		statement, linkProof.DigitCommitments, values, linkWitness.Blindings, int(context.Profile.chunkBits),
	)
	if err != nil {
		return nil, err
	}
	return &cvFallbackRangeProofV2{backend: cvFallbackRangeBackendV2, proof: proof}, nil
}

func cvVerifyFallbackRangeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofV2,
	rangeProof *cvFallbackRangeProofV2,
) error {
	if err := cvVerifyFallbackLinkV2(context, dealerID, offers, receiverPublicKeys, linkProof); err != nil {
		return err
	}
	return cvVerifyFallbackRangeAfterLinkV2(
		context, dealerID, offers, receiverPublicKeys, linkProof, rangeProof,
	)
}

func cvVerifyFallbackRangeAfterLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofV2,
	rangeProof *cvFallbackRangeProofV2,
) error {
	if context == nil {
		return fmt.Errorf("invalid CV V2 fallback-range proof")
	}
	chunks, err := cvChunkCount(context.Profile)
	total := len(offers) * chunks
	if err != nil || rangeProof == nil || rangeProof.backend != cvFallbackRangeBackendV2 || rangeProof.proof == nil ||
		dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) ||
		!cvValidFallbackLinkProofShapeAfterValidationV2(linkProof, total, len(offers)) ||
		rangeProof.proof.valueCount != total || rangeProof.proof.bits != int(context.Profile.chunkBits) {
		return fmt.Errorf("invalid CV V2 fallback-range proof")
	}
	statement, err := cvFallbackRangeStatementAfterValidationV2(
		context, dealerID, offers, receiverPublicKeys, linkProof,
	)
	if err != nil {
		return err
	}
	if err := apvssVerifyCompactRange(
		statement, linkProof.DigitCommitments, rangeProof.proof, int(context.Profile.chunkBits),
	); err != nil {
		return fmt.Errorf("invalid CV V2 aggregated fallback range: %w", err)
	}
	return nil
}

func cvFallbackRangeStatementV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofV2,
) ([]byte, error) {
	_, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || !cvValidFallbackLinkProofShapeV2(linkProof, total, len(offers)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range statement")
	}
	return cvFallbackRangeStatementModeV2(context, dealerID, offers, receiverPublicKeys, linkProof, true)
}

func cvFallbackRangeStatementAfterValidationV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofV2,
) ([]byte, error) {
	if context == nil || dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) || linkProof == nil {
		return nil, fmt.Errorf("invalid verified CV V2 fallback-range statement")
	}
	return cvFallbackRangeStatementModeV2(context, dealerID, offers, receiverPublicKeys, linkProof, false)
}

func cvFallbackRangeStatementModeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofV2, validatePoints bool,
) ([]byte, error) {
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return nil, err
	}
	var linkWire []byte
	if validatePoints {
		linkWire, err = cvFallbackLinkProofV2CanonicalBytes(linkProof, context, len(offers))
	} else {
		linkWire, err = cvFallbackLinkProofV2CanonicalBytesAfterValidation(linkProof, context, len(offers))
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeStatementDomainV2))
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(dealerID))
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeBackendV2))
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
	_ = cvWriteBytes(&wire, linkWire)
	return hashBytes([]byte(cvFallbackRangeStatementDomainV2), wire.Bytes()), nil
}

func cvFallbackRangeProofV2CanonicalBytes(proof *cvFallbackRangeProofV2) ([]byte, error) {
	if proof == nil || proof.backend != cvFallbackRangeBackendV2 || proof.proof == nil {
		return nil, fmt.Errorf("invalid CV V2 fallback-range wire")
	}
	backendWire, err := apvssCompactRangeProofCanonicalBytes(proof.proof)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeWireDomainV2))
	_ = cvWriteBytes(&wire, []byte(proof.backend))
	_ = cvWriteBytes(&wire, backendWire)
	return wire.Bytes(), nil
}

func cvDecodeFallbackRangeProofV2(
	wire []byte, context *cvLeafContextV2, fallbackCount int,
) (*cvFallbackRangeProofV2, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || fallbackCount <= 0 || fallbackCount > cvNewFaultBoundFromContextV2(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range decode parameters")
	}
	total := fallbackCount * chunks
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackRangeWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackRangeWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range domain")
	}
	backend, err := r.bytes(len(cvFallbackRangeBackendV2))
	if err != nil || !bytes.Equal(backend, []byte(cvFallbackRangeBackendV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range backend")
	}
	backendWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 fallback-range framing")
	}
	decoded, err := apvssDecodeCompactRangeProof(backendWire, total, int(context.Profile.chunkBits))
	if err != nil {
		return nil, err
	}
	proof := &cvFallbackRangeProofV2{backend: cvFallbackRangeBackendV2, proof: decoded}
	canonical, err := cvFallbackRangeProofV2CanonicalBytes(proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback-range proof")
	}
	return proof, nil
}
