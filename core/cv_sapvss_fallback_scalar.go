package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const cvFallbackEvidenceWireDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/fallback-evidence"

type cvFallbackEvidenceScalar struct {
	ReceiverIndices []int
	Link            cvFallbackLinkProofScalar
	Range           cvFallbackRangeProofScalar
}

func cvBuildFallbackEvidenceScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, witnesses []*cvDealerReceiverWitnessScalar,
) (*cvFallbackEvidenceScalar, error) {
	link, linkWitness, err := cvProveFallbackLinkScalar(context, dealerID, offers, receiverPublicKeys, witnesses)
	if err != nil {
		return nil, err
	}
	rangeProof, err := cvProveFallbackRangeAfterLinkScalar(
		context, dealerID, offers, receiverPublicKeys, witnesses, link, linkWitness,
	)
	if err != nil {
		return nil, err
	}
	indices := make([]int, len(offers))
	for i := range offers {
		indices[i] = offers[i].ReceiverIndex
	}
	return &cvFallbackEvidenceScalar{ReceiverIndices: indices, Link: *link, Range: *rangeProof}, nil
}

func cvVerifyFallbackEvidenceScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, evidence *cvFallbackEvidenceScalar,
) error {
	return cvVerifyFallbackEvidenceModeScalar(context, dealerID, offers, receiverPublicKeys, evidence, true)
}

func cvVerifyFallbackEvidenceAfterPointDecodingScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, evidence *cvFallbackEvidenceScalar,
) error {
	return cvVerifyFallbackEvidenceModeScalar(context, dealerID, offers, receiverPublicKeys, evidence, false)
}

func cvVerifyFallbackEvidenceModeScalar(
	context *cvLeafContextScalar, dealerID int, offers []*cvReceiverLaneOfferScalar,
	receiverPublicKeys []bls12381.G1Affine, evidence *cvFallbackEvidenceScalar, validatePoints bool,
) error {
	if evidence == nil || len(evidence.ReceiverIndices) != len(offers) {
		return fmt.Errorf("invalid CV V2 fallback evidence")
	}
	for i := range offers {
		if offers[i] == nil || evidence.ReceiverIndices[i] != offers[i].ReceiverIndex {
			return fmt.Errorf("CV V2 fallback evidence receiver mismatch")
		}
	}
	var linkErr error
	if validatePoints {
		linkErr = cvVerifyFallbackLinkScalar(context, dealerID, offers, receiverPublicKeys, &evidence.Link)
	} else {
		linkErr = cvVerifyFallbackLinkAfterPointDecodingScalar(
			context, dealerID, offers, receiverPublicKeys, &evidence.Link,
		)
	}
	if linkErr != nil {
		return linkErr
	}
	return cvVerifyFallbackRangeAfterLinkScalar(
		context, dealerID, offers, receiverPublicKeys, &evidence.Link, &evidence.Range,
	)
}

func cvFallbackEvidenceScalarCanonicalBytes(evidence *cvFallbackEvidenceScalar, context *cvLeafContextScalar) ([]byte, error) {
	return cvFallbackEvidenceScalarCanonicalBytesMode(evidence, context, true)
}

func cvFallbackEvidenceScalarCanonicalBytesAfterValidation(
	evidence *cvFallbackEvidenceScalar, context *cvLeafContextScalar,
) ([]byte, error) {
	return cvFallbackEvidenceScalarCanonicalBytesMode(evidence, context, false)
}

func cvFallbackEvidenceScalarCanonicalBytesMode(
	evidence *cvFallbackEvidenceScalar, context *cvLeafContextScalar, validatePoints bool,
) ([]byte, error) {
	if evidence == nil || len(evidence.ReceiverIndices) == 0 ||
		len(evidence.ReceiverIndices) > cvNewFaultBoundFromContextScalar(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence wire")
	}
	previous := 0
	for _, index := range evidence.ReceiverIndices {
		if index <= previous || index > len(context.NewRoster) {
			return nil, fmt.Errorf("invalid CV V2 fallback evidence indices")
		}
		previous = index
	}
	var linkWire []byte
	var err error
	if validatePoints {
		linkWire, err = cvFallbackLinkProofScalarCanonicalBytes(&evidence.Link, context, len(evidence.ReceiverIndices))
	} else {
		linkWire, err = cvFallbackLinkProofScalarCanonicalBytesAfterValidation(
			&evidence.Link, context, len(evidence.ReceiverIndices),
		)
	}
	if err != nil {
		return nil, err
	}
	rangeWire, err := cvFallbackRangeProofScalarCanonicalBytes(&evidence.Range)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackEvidenceWireDomainScalar))
	if err := cvWriteIndexVectorScalar(&wire, evidence.ReceiverIndices); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, linkWire)
	_ = cvWriteBytes(&wire, rangeWire)
	return wire.Bytes(), nil
}

func cvDecodeFallbackEvidenceScalar(wire []byte, context *cvLeafContextScalar) (*cvFallbackEvidenceScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackEvidenceWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackEvidenceWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence domain")
	}
	indices, err := cvReadIndexVectorScalar(r, cvNewFaultBoundFromContextScalar(context))
	if err != nil || len(indices) == 0 {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence indices")
	}
	linkWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback link framing")
	}
	rangeWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 fallback range framing")
	}
	link, err := cvDecodeFallbackLinkProofScalar(linkWire, context, len(indices))
	if err != nil {
		return nil, err
	}
	rangeProof, err := cvDecodeFallbackRangeProofScalar(rangeWire, context, len(indices))
	if err != nil {
		return nil, err
	}
	evidence := &cvFallbackEvidenceScalar{ReceiverIndices: indices, Link: *link, Range: *rangeProof}
	canonical, err := cvFallbackEvidenceScalarCanonicalBytesAfterValidation(evidence, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback evidence")
	}
	return evidence, nil
}
