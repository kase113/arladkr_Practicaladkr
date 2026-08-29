package core

import (
	"bytes"
	"fmt"
)

const (
	cvHandoffScalarDomain                  = "ARL-CV-sAPVSS/v2-scalar-group/handoff"
	cvHandoffDigestScalarDomain            = "ARL-CV-sAPVSS/v2-scalar-group/handoff-digest"
	cvDecisionCertificateScalarDomain      = "ARL-CV-sAPVSS/v2-scalar-group/decide"
	cvAggregateRecoveryRequestScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-recovery-request"
)

// cvHandoffScalar is the only agreement artifact intended to cross from the old
// committee to the new committee. Pool, PoolCert, contributor coin and VCert
// cannot be represented by this codec.
type cvHandoffScalar struct {
	ContextDigest []byte
	Header        cvAggregateHeaderScalar
	ARC           cvAPDBLockScalar
	DecCert       []byte
	// canonicalWire is populated by the strict decoder and reused by the
	// authorization path to avoid a second handoff encode.
	canonicalWire []byte
}

type cvAggregateRecoveryRequestScalar struct {
	Handoff       cvHandoffScalar
	canonicalWire []byte
}

func cvHandoffUnsignedScalarCanonicalBytes(contextDigest []byte, header *cvAggregateHeaderScalar, arc *cvAPDBLockScalar) ([]byte, error) {
	if len(contextDigest) != 32 || header == nil || arc == nil || !bytes.Equal(contextDigest, header.ContextDigest) ||
		!bytes.Equal(header.APDBInstance, arc.InstanceDigest) || !bytes.Equal(header.APDBRoot, arc.Root) {
		return nil, fmt.Errorf("invalid CV V2 handoff binding")
	}
	headerWire, err := cvAggregateHeaderScalarCanonicalBytes(header)
	if err != nil {
		return nil, err
	}
	arcWire, err := cvAPDBLockScalarCanonicalBytes(arc)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextDigest)
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, arcWire)
	return wire.Bytes(), nil
}

func cvHandoffDigestScalar(contextDigest []byte, header *cvAggregateHeaderScalar, arc *cvAPDBLockScalar) ([]byte, error) {
	unsigned, err := cvHandoffUnsignedScalarCanonicalBytes(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvHandoffDigestScalarDomain), unsigned), nil
}

func cvDecisionStatementScalar(contextDigest []byte, header *cvAggregateHeaderScalar, arc *cvAPDBLockScalar) ([]byte, error) {
	handoffDigest, err := cvHandoffDigestScalar(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvDecisionCertificateScalarDomain), contextDigest, handoffDigest), nil
}

func cvHandoffScalarCanonicalBytes(handoff *cvHandoffScalar) ([]byte, error) {
	if handoff == nil || len(handoff.DecCert) == 0 || len(handoff.DecCert) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 handoff")
	}
	if len(handoff.canonicalWire) != 0 {
		return handoff.canonicalWire, nil
	}
	unsigned, err := cvHandoffUnsignedScalarCanonicalBytes(handoff.ContextDigest, &handoff.Header, &handoff.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvHandoffScalarDomain))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, handoff.DecCert)
	return wire.Bytes(), nil
}

func cvDecodeHandoffScalar(wire []byte) (*cvHandoffScalar, error) {
	if len(wire) == 0 || len(wire) > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("invalid CV V2 handoff wire size")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvHandoffScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvHandoffScalarDomain)) {
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
	header, err := cvDecodeAggregateHeaderScalar(headerWire)
	if err != nil {
		return nil, err
	}
	arcWire, err := unsigned.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || unsigned.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 handoff ARC")
	}
	arc, err := cvDecodeAPDBLockScalar(arcWire)
	if err != nil {
		return nil, err
	}
	handoff := &cvHandoffScalar{ContextDigest: contextDigest, Header: *header, ARC: *arc, DecCert: decCert}
	canonical, err := cvHandoffScalarCanonicalBytes(handoff)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 handoff")
	}
	handoff.canonicalWire = canonical
	return handoff, nil
}

func cvVerifyHandoffScalar(handoff *cvHandoffScalar, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner) error {
	if _, err := cvHandoffScalarCanonicalBytes(handoff); err != nil {
		return err
	}
	return cvVerifyDecodedHandoffScalar(handoff, expectedContext, apdbSigner, controlSigner)
}

func cvVerifyDecodedHandoffScalar(
	handoff *cvHandoffScalar, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner,
) error {
	if handoff == nil || len(expectedContext) != 32 || !cvScalarSignerHasRole(apdbSigner, cvScalarRoleAPDB) ||
		!cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) ||
		!bytes.Equal(handoff.ContextDigest, expectedContext) {
		return fmt.Errorf("invalid CV V2 handoff verification input")
	}
	if err := cvVerifyAPDBLockScalar(&handoff.ARC, apdbSigner); err != nil {
		return err
	}
	statement, err := cvDecisionStatementScalar(handoff.ContextDigest, &handoff.Header, &handoff.ARC)
	if err != nil || !controlSigner.VerifyRecovered(cvDecisionCertificateScalarDomain, statement, handoff.DecCert) {
		return fmt.Errorf("invalid CV V2 decision certificate")
	}
	return nil
}

func cvAggregateRecoveryRequestScalarCanonicalBytes(request *cvAggregateRecoveryRequestScalar) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("nil CV V2 aggregate recovery request")
	}
	if len(request.canonicalWire) != 0 {
		return request.canonicalWire, nil
	}
	handoffWire, err := cvHandoffScalarCanonicalBytes(&request.Handoff)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateRecoveryRequestScalarDomain))
	_ = cvWriteBytes(&wire, handoffWire)
	return wire.Bytes(), nil
}

func cvDecodeAggregateRecoveryRequestScalar(wire []byte) (*cvAggregateRecoveryRequestScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateRecoveryRequestScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateRecoveryRequestScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request domain")
	}
	handoffWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request framing")
	}
	handoff, err := cvDecodeHandoffScalar(handoffWire)
	if err != nil {
		return nil, err
	}
	request := &cvAggregateRecoveryRequestScalar{Handoff: *handoff}
	canonical, err := cvAggregateRecoveryRequestScalarCanonicalBytes(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate recovery request")
	}
	request.canonicalWire = canonical
	return request, nil
}

func cvAuthorizeAggregateRecoveryRequestScalar(
	wire, expectedContext []byte, apdbSigner, controlSigner *tblsThresholdSigner,
) (*cvHandoffScalar, error) {
	request, err := cvDecodeAggregateRecoveryRequestScalar(wire)
	if err != nil {
		return nil, err
	}
	if err := cvVerifyHandoffScalar(&request.Handoff, expectedContext, apdbSigner, controlSigner); err != nil {
		return nil, fmt.Errorf("unauthorized CV V2 aggregate recovery request: %w", err)
	}
	return &request.Handoff, nil
}
