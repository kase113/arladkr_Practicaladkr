package core

import (
	"bytes"
	"fmt"
)

const (
	cvComponentHeaderScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/component-header"
	cvComponentRefScalarDomain    = "ARL-CV-sAPVSS/v2-scalar-group/component-ref"
	cvPoolScalarDomain            = "ARL-CV-sAPVSS/v2-scalar-group/pool"
	cvPoolDigestScalarDomain      = "ARL-CV-sAPVSS/v2-scalar-group/pool-digest"
	cvPoolCertScalarDomain        = "ARL-CV-sAPVSS/v2-scalar-group/pool-cert"
	cvPoolCertShareScalarDomain   = "ARL-CV-sAPVSS/v2-scalar-group/pool-cert-share-wire"
)

type cvComponentHeaderScalar struct {
	ContextDigest []byte
	DealerID      int
	PayloadDigest []byte
	Instance      []byte
	Root          []byte
}

type cvComponentRefScalar struct {
	Header cvComponentHeaderScalar
	Lock   cvAPDBLockScalar
}

type cvPoolScalar struct {
	ContextDigest []byte
	ProposerID    int
	Components    []cvComponentRefScalar
	Digest        []byte
}

type cvPoolCertificateScalar struct {
	PoolDigest    []byte
	Certificate   []byte
	canonicalWire []byte
}

type cvPoolCertificateShareScalar struct {
	ProposerID int
	PoolDigest []byte
	Signature  []byte
}

func cvPoolCertificateShareScalarCanonicalBytes(share *cvPoolCertificateShareScalar) ([]byte, error) {
	if share == nil || share.ProposerID < 0 || len(share.PoolDigest) != 32 || len(share.Signature) == 0 ||
		len(share.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvPoolCertShareScalarDomain))
	cvWriteUint64(&wire, uint64(share.ProposerID))
	_ = cvWriteBytes(&wire, share.PoolDigest)
	_ = cvWriteBytes(&wire, share.Signature)
	return wire.Bytes(), nil
}

func cvDecodePoolCertificateShareScalar(wire []byte) (*cvPoolCertificateShareScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvPoolCertShareScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolCertShareScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share domain")
	}
	proposer, err := r.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share proposer")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share digest")
	}
	signature, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(signature) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share signature")
	}
	share := &cvPoolCertificateShareScalar{ProposerID: int(proposer), PoolDigest: digest, Signature: signature}
	canonical, err := cvPoolCertificateShareScalarCanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool certificate share")
	}
	return share, nil
}

type cvPoolSlotStateScalar struct {
	poolDigest []byte
	poolSeen   bool
	signed     bool
	certSeen   bool
}

func cvComponentInstanceDigestScalar(contextDigest []byte, dealerID int) ([]byte, error) {
	if len(contextDigest) != 32 || dealerID < 0 {
		return nil, fmt.Errorf("invalid CV V2 component instance input")
	}
	var dealer bytes.Buffer
	cvWriteUint64(&dealer, uint64(dealerID))
	return cvAPDBInstanceDigestScalar("COMP", contextDigest, dealer.Bytes())
}

func cvComponentHeaderScalarCanonicalBytes(header cvComponentHeaderScalar) ([]byte, error) {
	if len(header.ContextDigest) != 32 || header.DealerID < 0 || len(header.PayloadDigest) != 32 ||
		len(header.Instance) != 32 || len(header.Root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 component header")
	}
	wantInstance, err := cvComponentInstanceDigestScalar(header.ContextDigest, header.DealerID)
	if err != nil || !bytes.Equal(wantInstance, header.Instance) {
		return nil, fmt.Errorf("CV V2 component header instance mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentHeaderScalarDomain))
	_ = cvWriteBytes(&wire, header.ContextDigest)
	cvWriteUint64(&wire, uint64(header.DealerID))
	_ = cvWriteBytes(&wire, header.PayloadDigest)
	_ = cvWriteBytes(&wire, header.Instance)
	_ = cvWriteBytes(&wire, header.Root)
	return wire.Bytes(), nil
}

func cvDecodeComponentHeaderScalar(wire []byte) (cvComponentHeaderScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentHeaderScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentHeaderScalarDomain)) {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header domain")
	}
	context, err := r.bytes(32)
	if err != nil || len(context) != 32 {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header dealer")
	}
	payload, err := r.bytes(32)
	if err != nil || len(payload) != 32 {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header payload")
	}
	instance, err := r.bytes(32)
	if err != nil || len(instance) != 32 {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 || r.reader.Len() != 0 {
		return cvComponentHeaderScalar{}, fmt.Errorf("invalid CV V2 component header root")
	}
	header := cvComponentHeaderScalar{ContextDigest: context, DealerID: int(dealer), PayloadDigest: payload, Instance: instance, Root: root}
	canonical, err := cvComponentHeaderScalarCanonicalBytes(header)
	if err != nil || !bytes.Equal(canonical, wire) {
		return cvComponentHeaderScalar{}, fmt.Errorf("non-canonical CV V2 component header")
	}
	return header, nil
}

func cvComponentRefScalarCanonicalBytes(ref cvComponentRefScalar) ([]byte, error) {
	headerWire, err := cvComponentHeaderScalarCanonicalBytes(ref.Header)
	if err != nil {
		return nil, err
	}
	lockWire, err := cvAPDBLockScalarCanonicalBytes(&ref.Lock)
	if err != nil || !bytes.Equal(ref.Header.Instance, ref.Lock.InstanceDigest) || !bytes.Equal(ref.Header.Root, ref.Lock.Root) {
		return nil, fmt.Errorf("invalid CV V2 component reference lock")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentRefScalarDomain))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, lockWire)
	return wire.Bytes(), nil
}

func cvDecodeComponentRefScalar(wire []byte) (cvComponentRefScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentRefScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentRefScalarDomain)) {
		return cvComponentRefScalar{}, fmt.Errorf("invalid CV V2 component reference domain")
	}
	headerWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil {
		return cvComponentRefScalar{}, fmt.Errorf("invalid CV V2 component reference header")
	}
	header, err := cvDecodeComponentHeaderScalar(headerWire)
	if err != nil {
		return cvComponentRefScalar{}, err
	}
	lockWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return cvComponentRefScalar{}, fmt.Errorf("invalid CV V2 component reference lock")
	}
	lock, err := cvDecodeAPDBLockScalar(lockWire)
	if err != nil {
		return cvComponentRefScalar{}, err
	}
	ref := cvComponentRefScalar{Header: header, Lock: *lock}
	canonical, err := cvComponentRefScalarCanonicalBytes(ref)
	if err != nil || !bytes.Equal(canonical, wire) {
		return cvComponentRefScalar{}, fmt.Errorf("non-canonical CV V2 component reference")
	}
	return ref, nil
}

func cvValidateComponentRefScalar(ref cvComponentRefScalar, apdbSigner *tblsThresholdSigner) error {
	if _, err := cvComponentRefScalarCanonicalBytes(ref); err != nil {
		return err
	}
	if apdbSigner != nil {
		return cvVerifyAPDBLockScalar(&ref.Lock, apdbSigner)
	}
	return nil
}

func cvPoolScalarCanonicalBytes(pool *cvPoolScalar, params cvScalarParams) ([]byte, error) {
	if pool == nil || len(pool.ContextDigest) != 32 || pool.ProposerID < 0 ||
		len(pool.Components) != params.poolSize || len(pool.Digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool")
	}
	var unsigned bytes.Buffer
	_ = cvWriteBytes(&unsigned, []byte(cvPoolScalarDomain))
	_ = cvWriteBytes(&unsigned, pool.ContextDigest)
	cvWriteUint64(&unsigned, uint64(pool.ProposerID))
	if err := cvWriteUint32(&unsigned, len(pool.Components)); err != nil {
		return nil, err
	}
	lastDealer := -1
	for _, ref := range pool.Components {
		if ref.Header.DealerID <= lastDealer || !bytes.Equal(ref.Header.ContextDigest, pool.ContextDigest) {
			return nil, fmt.Errorf("invalid CV V2 pool component order")
		}
		refWire, err := cvComponentRefScalarCanonicalBytes(ref)
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&unsigned, refWire)
		lastDealer = ref.Header.DealerID
	}
	wantDigest := hashBytes([]byte(cvPoolDigestScalarDomain), unsigned.Bytes())
	if !bytes.Equal(pool.Digest, wantDigest) {
		return nil, fmt.Errorf("CV V2 pool digest mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, unsigned.Bytes())
	_ = cvWriteBytes(&wire, pool.Digest)
	return wire.Bytes(), nil
}

func cvBuildPoolScalar(contextDigest []byte, proposerID int, components []cvComponentRefScalar, params cvScalarParams) (*cvPoolScalar, error) {
	pool := &cvPoolScalar{ContextDigest: append([]byte(nil), contextDigest...), ProposerID: proposerID,
		Components: append([]cvComponentRefScalar(nil), components...)}
	if len(pool.ContextDigest) != 32 || len(pool.Components) != params.poolSize {
		return nil, fmt.Errorf("invalid CV V2 pool construction")
	}
	var unsigned bytes.Buffer
	_ = cvWriteBytes(&unsigned, []byte(cvPoolScalarDomain))
	_ = cvWriteBytes(&unsigned, pool.ContextDigest)
	cvWriteUint64(&unsigned, uint64(pool.ProposerID))
	if err := cvWriteUint32(&unsigned, len(pool.Components)); err != nil {
		return nil, err
	}
	lastDealer := -1
	for _, ref := range pool.Components {
		if ref.Header.DealerID <= lastDealer || !bytes.Equal(ref.Header.ContextDigest, pool.ContextDigest) {
			return nil, fmt.Errorf("invalid CV V2 pool construction order")
		}
		refWire, err := cvComponentRefScalarCanonicalBytes(ref)
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&unsigned, refWire)
		lastDealer = ref.Header.DealerID
	}
	pool.Digest = hashBytes([]byte(cvPoolDigestScalarDomain), unsigned.Bytes())
	if _, err := cvPoolScalarCanonicalBytes(pool, params); err != nil {
		return nil, err
	}
	return pool, nil
}

func cvDecodePoolScalar(wire []byte, params cvScalarParams) (*cvPoolScalar, error) {
	r := newCVWireReader(wire)
	unsignedWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 pool unsigned body")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 pool digest")
	}
	unsigned := newCVWireReader(unsignedWire)
	domain, err := unsigned.bytes(len(cvPoolScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 pool domain")
	}
	context, err := unsigned.bytes(32)
	if err != nil || len(context) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool context")
	}
	proposer, err := unsigned.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 pool proposer")
	}
	count, err := unsigned.uint32()
	if err != nil || count != params.poolSize {
		return nil, fmt.Errorf("invalid CV V2 pool component count")
	}
	components := make([]cvComponentRefScalar, count)
	for i := range components {
		refWire, readErr := unsigned.bytes(cvMaxNetworkPayloadBytes)
		if readErr != nil {
			return nil, fmt.Errorf("invalid CV V2 pool component")
		}
		components[i], readErr = cvDecodeComponentRefScalar(refWire)
		if readErr != nil {
			return nil, readErr
		}
	}
	if unsigned.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 pool unsigned suffix")
	}
	pool := &cvPoolScalar{ContextDigest: context, ProposerID: int(proposer), Components: components, Digest: digest}
	canonical, err := cvPoolScalarCanonicalBytes(pool, params)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool")
	}
	return pool, nil
}

func cvPoolCertificateScalarCanonicalBytes(certificate *cvPoolCertificateScalar) ([]byte, error) {
	if certificate == nil || len(certificate.PoolDigest) != 32 || len(certificate.Certificate) == 0 ||
		len(certificate.Certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 pool certificate")
	}
	if len(certificate.canonicalWire) != 0 {
		return certificate.canonicalWire, nil
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvPoolCertScalarDomain))
	_ = cvWriteBytes(&wire, certificate.PoolDigest)
	_ = cvWriteBytes(&wire, certificate.Certificate)
	return wire.Bytes(), nil
}

func cvDecodePoolCertificateScalar(wire []byte) (*cvPoolCertificateScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvPoolCertScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolCertScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 pool certificate domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate digest")
	}
	certificateWire, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificateWire) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate signature")
	}
	certificate := &cvPoolCertificateScalar{PoolDigest: digest, Certificate: certificateWire}
	canonical, err := cvPoolCertificateScalarCanonicalBytes(certificate)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool certificate")
	}
	certificate.canonicalWire = canonical
	return certificate, nil
}

func cvPoolCertificateStatementScalar(contextDigest []byte, proposerID int, poolDigest []byte) ([]byte, error) {
	if len(contextDigest) != 32 || proposerID < 0 || len(poolDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate statement")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(proposerID))
	_ = cvWriteBytes(&wire, poolDigest)
	return hashBytes([]byte(cvPoolCertScalarDomain), wire.Bytes()), nil
}

func cvVerifyPoolCertificateScalar(pool *cvPoolScalar, certificate *cvPoolCertificateScalar, controlSigner *tblsThresholdSigner) error {
	if pool == nil || certificate == nil || !cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) || !bytes.Equal(pool.Digest, certificate.PoolDigest) {
		return fmt.Errorf("invalid CV V2 pool certificate")
	}
	statement, err := cvPoolCertificateStatementScalar(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil || !controlSigner.VerifyRecovered(cvPoolCertScalarDomain, statement, certificate.Certificate) {
		return fmt.Errorf("invalid CV V2 pool certificate signature")
	}
	return nil
}

func (state *cvPoolSlotStateScalar) observePool(pool *cvPoolScalar) error {
	if state == nil || pool == nil || len(pool.Digest) != 32 {
		return fmt.Errorf("invalid CV V2 pool slot input")
	}
	if state.poolSeen && !bytes.Equal(state.poolDigest, pool.Digest) {
		return fmt.Errorf("conflicting CV V2 pool for proposer slot")
	}
	if !state.poolSeen {
		state.poolSeen = true
		state.poolDigest = append([]byte(nil), pool.Digest...)
	}
	return nil
}

func (state *cvPoolSlotStateScalar) markSigned(poolDigest []byte) error {
	if state == nil || !state.poolSeen || !bytes.Equal(state.poolDigest, poolDigest) || state.signed {
		return fmt.Errorf("invalid CV V2 pool slot signature transition")
	}
	state.signed = true
	return nil
}

func (state *cvPoolSlotStateScalar) observeCertificate(certificate *cvPoolCertificateScalar) error {
	if state == nil || !state.poolSeen || certificate == nil || !bytes.Equal(state.poolDigest, certificate.PoolDigest) {
		return fmt.Errorf("conflicting CV V2 pool certificate for proposer slot")
	}
	state.certSeen = true
	return nil
}
