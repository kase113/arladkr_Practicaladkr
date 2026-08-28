package core

import (
	"bytes"
	"fmt"
)

const (
	cvHandoffV2Domain                  = "ARL-CV-sAPVSS/v2-scalar-group/handoff"
	cvHandoffDigestV2Domain            = "ARL-CV-sAPVSS/v2-scalar-group/handoff-digest"
	cvDecisionCertificateV2Domain      = "ARL-CV-sAPVSS/v2-scalar-group/decide"
	cvAggregateRecoveryRequestV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-recovery-request"
)

// cvHandoffV2 is the only agreement artifact intended to cross from the old
// committee to the new committee. Pool, PoolCert, contributor coin and VCert
// cannot be represented by this codec.
type cvHandoffV2 struct {
	ContextDigest []byte
	Header        cvAggregateHeaderV2
	ARC           cvAPDBLockV2
	DecCert       []byte
	// canonicalWire is populated by the strict decoder and reused by the
	// authorization path to avoid a second handoff encode.
	canonicalWire []byte
}

type cvAggregateRecoveryRequestV2 struct {
	Handoff       cvHandoffV2
	canonicalWire []byte
}

func cvHandoffUnsignedV2CanonicalBytes(contextDigest []byte, header *cvAggregateHeaderV2, arc *cvAPDBLockV2) ([]byte, error) {
	if len(contextDigest) != 32 || header == nil || arc == nil || !bytes.Equal(contextDigest, header.ContextDigest) ||
		!bytes.Equal(header.APDBInstance, arc.InstanceDigest) || !bytes.Equal(header.APDBRoot, arc.Root) {
		return nil, fmt.Errorf("invalid CV V2 handoff binding")
	}
	headerWire, err := cvAggregateHeaderV2CanonicalBytes(header)
	if err != nil {
		return nil, err
	}
	arcWire, err := cvAPDBLockV2CanonicalBytes(arc)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextDigest)
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, arcWire)
	return wire.Bytes(), nil
}

func cvHandoffDigestV2(contextDigest []byte, header *cvAggregateHeaderV2, arc *cvAPDBLockV2) ([]byte, error) {
	unsigned, err := cvHandoffUnsignedV2CanonicalBytes(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvHandoffDigestV2Domain), unsigned), nil
}

func cvDecisionStatementV2(contextDigest []byte, header *cvAggregateHeaderV2, arc *cvAPDBLockV2) ([]byte, error) {
	handoffDigest, err := cvHandoffDigestV2(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvDecisionCertificateV2Domain), contextDigest, handoffDigest), nil
}

func cvHandoffV2CanonicalBytes(handoff *cvHandoffV2) ([]byte, error) {
	if handoff == nil || len(handoff.DecCert) == 0 || len(handoff.DecCert) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 handoff")
	}
	if len(handoff.canonicalWire) != 0 {
		return handoff.canonicalWire, nil
	}
	unsigned, err := cvHandoffUnsignedV2CanonicalBytes(handoff.ContextDigest, &handoff.Header, &handoff.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvHandoffV2Domain))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, handoff.DecCert)
	return wire.Bytes(), nil
}

func cvDecodeHandoffV2(wire []byte) (*cvHandoffV2, error) {
	if len(wire) == 0 || len(wire) > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("invalid CV V2 handoff wire size")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvHandoffV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvHandoffV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 handoff domain")
	}
	unsignedWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 handoff body")
	}
	decCert, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(decCert) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 decision certificate")
	}
	unsigned := newCVWireReader(unsignedWire)
	contextDigest, err := unsigned.bytes(32)
	if err != nil || len(contextDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 handoff context")
	}
	headerWire, err := unsigned.bytes(1 << 12)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 handoff header")
	}
	header, err := cvDecodeAggregateHeaderV2(headerWire)
	if err != nil {
		return nil, err
	}
	arcWire, err := unsigned.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || unsigned.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 handoff ARC")
	}
	arc, err := cvDecodeAPDBLockV2(arcWire)
	if err != nil {
		return nil, err
	}
	handoff := &cvHandoffV2{ContextDigest: contextDigest, Header: *header, ARC: *arc, DecCert: decCert}
	canonical, err := cvHandoffV2CanonicalBytes(handoff)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 handoff")
	}
	handoff.canonicalWire = canonical
	return handoff, nil
}

func cvVerifyHandoffV2(handoff *cvHandoffV2, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner) error {
	if _, err := cvHandoffV2CanonicalBytes(handoff); err != nil {
		return err
	}
	return cvVerifyDecodedHandoffV2(handoff, expectedContext, apdbSigner, controlSigner)
}

func cvVerifyDecodedHandoffV2(
	handoff *cvHandoffV2, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner,
) error {
	if handoff == nil || len(expectedContext) != 32 || !cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!bytes.Equal(handoff.ContextDigest, expectedContext) {
		return fmt.Errorf("invalid CV V2 handoff verification input")
	}
	if err := cvVerifyAPDBLockV2(&handoff.ARC, apdbSigner); err != nil {
		return err
	}
	statement, err := cvDecisionStatementV2(handoff.ContextDigest, &handoff.Header, &handoff.ARC)
	if err != nil || !controlSigner.VerifyRecovered(cvDecisionCertificateV2Domain, statement, handoff.DecCert) {
		return fmt.Errorf("invalid CV V2 decision certificate")
	}
	return nil
}

func cvAggregateRecoveryRequestV2CanonicalBytes(request *cvAggregateRecoveryRequestV2) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("nil CV V2 aggregate recovery request")
	}
	if len(request.canonicalWire) != 0 {
		return request.canonicalWire, nil
	}
	handoffWire, err := cvHandoffV2CanonicalBytes(&request.Handoff)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateRecoveryRequestV2Domain))
	_ = cvWriteBytes(&wire, handoffWire)
	return wire.Bytes(), nil
}

func cvDecodeAggregateRecoveryRequestV2(wire []byte) (*cvAggregateRecoveryRequestV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateRecoveryRequestV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateRecoveryRequestV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request domain")
	}
	handoffWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request framing")
	}
	handoff, err := cvDecodeHandoffV2(handoffWire)
	if err != nil {
		return nil, err
	}
	request := &cvAggregateRecoveryRequestV2{Handoff: *handoff}
	canonical, err := cvAggregateRecoveryRequestV2CanonicalBytes(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate recovery request")
	}
	request.canonicalWire = canonical
	return request, nil
}

func cvAuthorizeAggregateRecoveryRequestV2(
	wire, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner,
) (*cvHandoffV2, error) {
	request, err := cvDecodeAggregateRecoveryRequestV2(wire)
	if err != nil {
		return nil, err
	}
	if err := cvVerifyHandoffV2(&request.Handoff, expectedContext, apdbSigner, controlSigner); err != nil {
		return nil, fmt.Errorf("unauthorized CV V2 aggregate recovery request: %w", err)
	}
	return &request.Handoff, nil
}
