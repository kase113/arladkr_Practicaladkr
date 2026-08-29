package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvFallbackRangeBackendScalar         = "bulletproofs-bls12381-aggregated-v1"
	cvFallbackRangeWireDomainScalar      = "ARL-CV-sAPVSS/v2-scalar-group/fallback-range"
	cvFallbackRangeStatementDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/fallback-range/statement"
)

// cvFallbackRangeProofScalar is a scalar protocol-domain adapter around the repository's
// standard aggregated Bulletproof implementation. It proves all flattened
// fallback digits against the exact commitments used by the link proof.
type cvFallbackRangeProofScalar struct {
	backend string
	proof   *apvssCompactRangeProof
}

func cvProveFallbackRangeScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessScalar,
	linkProof *cvFallbackLinkProofScalar, linkWitness *cvFallbackDigitWitnessScalar,
) (*cvFallbackRangeProofScalar, error) {
	return cvProveFallbackRangeModeScalar(
		context, dealerID, offers, receiverPublicKeys, dealerWitnesses, linkProof, linkWitness, true,
	)
}

func cvProveFallbackRangeAfterLinkScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessScalar,
	linkProof *cvFallbackLinkProofScalar, linkWitness *cvFallbackDigitWitnessScalar,
) (*cvFallbackRangeProofScalar, error) {
	return cvProveFallbackRangeModeScalar(
		context, dealerID, offers, receiverPublicKeys, dealerWitnesses, linkProof, linkWitness, false,
	)
}

func cvProveFallbackRangeModeScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, dealerWitnesses []*cvDealerReceiverWitnessScalar,
	linkProof *cvFallbackLinkProofScalar, linkWitness *cvFallbackDigitWitnessScalar, validateLink bool,
) (*cvFallbackRangeProofScalar, error) {
	var chunks, total int
	var err error
	if validateLink {
		chunks, total, err = cvValidateFallbackLinkStatementScalar(context, dealerID, offers, receiverPublicKeys)
	} else {
		chunks, total, err = cvValidateFallbackLinkStatementAfterPointDecodingScalar(
			context, dealerID, offers, receiverPublicKeys,
		)
	}
	if err != nil || len(dealerWitnesses) != len(offers) || linkWitness == nil ||
		len(linkWitness.Blindings) != total ||
		(validateLink && !cvValidFallbackLinkProofShapeScalar(linkProof, total, len(offers))) ||
		(!validateLink && !cvValidFallbackLinkProofShapeAfterValidationScalar(linkProof, total, len(offers))) {
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
			position := cvFallbackLinkPositionScalar(receiver, chunk, chunks)
			values[position] = witness.ScalarDigits[chunk]
		}
	}
	var statement []byte
	if validateLink {
		statement, err = cvFallbackRangeStatementScalar(context, dealerID, offers, receiverPublicKeys, linkProof)
	} else {
		statement, err = cvFallbackRangeStatementAfterValidationScalar(
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
	return &cvFallbackRangeProofScalar{backend: cvFallbackRangeBackendScalar, proof: proof}, nil
}

func cvVerifyFallbackRangeScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofScalar,
	rangeProof *cvFallbackRangeProofScalar,
) error {
	if err := cvVerifyFallbackLinkScalar(context, dealerID, offers, receiverPublicKeys, linkProof); err != nil {
		return err
	}
	return cvVerifyFallbackRangeAfterLinkScalar(
		context, dealerID, offers, receiverPublicKeys, linkProof, rangeProof,
	)
}

func cvVerifyFallbackRangeAfterLinkScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofScalar,
	rangeProof *cvFallbackRangeProofScalar,
) error {
	if context == nil {
		return fmt.Errorf("invalid CV V2 fallback-range proof")
	}
	chunks, err := cvChunkCount(context.Profile)
	total := len(offers) * chunks
	if err != nil || rangeProof == nil || rangeProof.backend != cvFallbackRangeBackendScalar || rangeProof.proof == nil ||
		dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) ||
		!cvValidFallbackLinkProofShapeAfterValidationScalar(linkProof, total, len(offers)) ||
		rangeProof.proof.valueCount != total || rangeProof.proof.bits != int(context.Profile.chunkBits) {
		return fmt.Errorf("invalid CV V2 fallback-range proof")
	}
	statement, err := cvFallbackRangeStatementAfterValidationScalar(
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

func cvFallbackRangeStatementScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofScalar,
) ([]byte, error) {
	_, total, err := cvValidateFallbackLinkStatementScalar(context, dealerID, offers, receiverPublicKeys)
	if err != nil || !cvValidFallbackLinkProofShapeScalar(linkProof, total, len(offers)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range statement")
	}
	return cvFallbackRangeStatementModeScalar(context, dealerID, offers, receiverPublicKeys, linkProof, true)
}

func cvFallbackRangeStatementAfterValidationScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofScalar,
) ([]byte, error) {
	if context == nil || dealerID < 0 || len(offers) == 0 || len(offers) != len(receiverPublicKeys) || linkProof == nil {
		return nil, fmt.Errorf("invalid verified CV V2 fallback-range statement")
	}
	return cvFallbackRangeStatementModeScalar(context, dealerID, offers, receiverPublicKeys, linkProof, false)
}

func cvFallbackRangeStatementModeScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, linkProof *cvFallbackLinkProofScalar, validatePoints bool,
) ([]byte, error) {
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return nil, err
	}
	var linkWire []byte
	if validatePoints {
		linkWire, err = cvFallbackLinkProofScalarCanonicalBytes(linkProof, context, len(offers))
	} else {
		linkWire, err = cvFallbackLinkProofScalarCanonicalBytesAfterValidation(linkProof, context, len(offers))
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeStatementDomainScalar))
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(dealerID))
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeBackendScalar))
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
	return hashBytes([]byte(cvFallbackRangeStatementDomainScalar), wire.Bytes()), nil
}

func cvFallbackRangeProofScalarCanonicalBytes(proof *cvFallbackRangeProofScalar) ([]byte, error) {
	if proof == nil || proof.backend != cvFallbackRangeBackendScalar || proof.proof == nil {
		return nil, fmt.Errorf("invalid CV V2 fallback-range wire")
	}
	backendWire, err := apvssCompactRangeProofCanonicalBytes(proof.proof)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackRangeWireDomainScalar))
	_ = cvWriteBytes(&wire, []byte(proof.backend))
	_ = cvWriteBytes(&wire, backendWire)
	return wire.Bytes(), nil
}

func cvDecodeFallbackRangeProofScalar(
	wire []byte, context *cvLeafContextScalar, fallbackCount int,
) (*cvFallbackRangeProofScalar, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || fallbackCount <= 0 || fallbackCount > cvNewFaultBoundFromContextScalar(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range decode parameters")
	}
	total := fallbackCount * chunks
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackRangeWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackRangeWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-range domain")
	}
	backend, err := r.bytes(len(cvFallbackRangeBackendScalar))
	if err != nil || !bytes.Equal(backend, []byte(cvFallbackRangeBackendScalar)) {
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
	proof := &cvFallbackRangeProofScalar{backend: cvFallbackRangeBackendScalar, proof: decoded}
	canonical, err := cvFallbackRangeProofScalarCanonicalBytes(proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback-range proof")
	}
	return proof, nil
}
