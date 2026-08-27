package core

import (
	"bytes"
	"fmt"
)

const (
	cvComponentHeaderV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/component-header"
	cvComponentRefV2Domain    = "ARL-CV-sAPVSS/v2-scalar-group/component-ref"
	cvPoolV2Domain            = "ARL-CV-sAPVSS/v2-scalar-group/pool"
	cvPoolDigestV2Domain      = "ARL-CV-sAPVSS/v2-scalar-group/pool-digest"
	cvPoolCertV2Domain        = "ARL-CV-sAPVSS/v2-scalar-group/pool-cert"
	cvPoolCertShareV2Domain   = "ARL-CV-sAPVSS/v2-scalar-group/pool-cert-share-wire"
)

type cvComponentHeaderV2 struct {
	ContextDigest []byte
	DealerID      int
	PayloadDigest []byte
	Instance      []byte
	Root          []byte
}

type cvComponentRefV2 struct {
	Header cvComponentHeaderV2
	Lock   cvAPDBLockV2
}

type cvPoolV2 struct {
	ContextDigest []byte
	ProposerID    int
	Components    []cvComponentRefV2
	Digest        []byte
}

type cvPoolCertificateV2 struct {
	PoolDigest    []byte
	Certificate   []byte
	canonicalWire []byte
}

type cvPoolCertificateShareV2 struct {
	ProposerID int
	PoolDigest []byte
	Signature  []byte
}

func cvPoolCertificateShareV2CanonicalBytes(share *cvPoolCertificateShareV2) ([]byte, error) {
	if share == nil || share.ProposerID < 0 || len(share.PoolDigest) != 32 || len(share.Signature) == 0 ||
		len(share.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 pool certificate share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvPoolCertShareV2Domain))
	cvWriteUint64(&wire, uint64(share.ProposerID))
	_ = cvWriteBytes(&wire, share.PoolDigest)
	_ = cvWriteBytes(&wire, share.Signature)
	return wire.Bytes(), nil
}

func cvDecodePoolCertificateShareV2(wire []byte) (*cvPoolCertificateShareV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvPoolCertShareV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolCertShareV2Domain)) {
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
	share := &cvPoolCertificateShareV2{ProposerID: int(proposer), PoolDigest: digest, Signature: signature}
	canonical, err := cvPoolCertificateShareV2CanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool certificate share")
	}
	return share, nil
}

type cvPoolSlotStateV2 struct {
	poolDigest []byte
	poolSeen   bool
	signed     bool
	certSeen   bool
}

func cvComponentInstanceDigestV2(contextDigest []byte, dealerID int) ([]byte, error) {
	if len(contextDigest) != 32 || dealerID < 0 {
		return nil, fmt.Errorf("invalid CV V2 component instance input")
	}
	var dealer bytes.Buffer
	cvWriteUint64(&dealer, uint64(dealerID))
	return cvAPDBInstanceDigestV2("COMP", contextDigest, dealer.Bytes())
}

func cvComponentHeaderV2CanonicalBytes(header cvComponentHeaderV2) ([]byte, error) {
	if len(header.ContextDigest) != 32 || header.DealerID < 0 || len(header.PayloadDigest) != 32 ||
		len(header.Instance) != 32 || len(header.Root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 component header")
	}
	wantInstance, err := cvComponentInstanceDigestV2(header.ContextDigest, header.DealerID)
	if err != nil || !bytes.Equal(wantInstance, header.Instance) {
		return nil, fmt.Errorf("CV V2 component header instance mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentHeaderV2Domain))
	_ = cvWriteBytes(&wire, header.ContextDigest)
	cvWriteUint64(&wire, uint64(header.DealerID))
	_ = cvWriteBytes(&wire, header.PayloadDigest)
	_ = cvWriteBytes(&wire, header.Instance)
	_ = cvWriteBytes(&wire, header.Root)
	return wire.Bytes(), nil
}

func cvDecodeComponentHeaderV2(wire []byte) (cvComponentHeaderV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentHeaderV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentHeaderV2Domain)) {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header domain")
	}
	context, err := r.bytes(32)
	if err != nil || len(context) != 32 {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header dealer")
	}
	payload, err := r.bytes(32)
	if err != nil || len(payload) != 32 {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header payload")
	}
	instance, err := r.bytes(32)
	if err != nil || len(instance) != 32 {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 || r.reader.Len() != 0 {
		return cvComponentHeaderV2{}, fmt.Errorf("invalid CV V2 component header root")
	}
	header := cvComponentHeaderV2{ContextDigest: context, DealerID: int(dealer), PayloadDigest: payload, Instance: instance, Root: root}
	canonical, err := cvComponentHeaderV2CanonicalBytes(header)
	if err != nil || !bytes.Equal(canonical, wire) {
		return cvComponentHeaderV2{}, fmt.Errorf("non-canonical CV V2 component header")
	}
	return header, nil
}

func cvComponentRefV2CanonicalBytes(ref cvComponentRefV2) ([]byte, error) {
	headerWire, err := cvComponentHeaderV2CanonicalBytes(ref.Header)
	if err != nil {
		return nil, err
	}
	lockWire, err := cvAPDBLockV2CanonicalBytes(&ref.Lock)
	if err != nil || !bytes.Equal(ref.Header.Instance, ref.Lock.InstanceDigest) || !bytes.Equal(ref.Header.Root, ref.Lock.Root) {
		return nil, fmt.Errorf("invalid CV V2 component reference lock")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentRefV2Domain))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, lockWire)
	return wire.Bytes(), nil
}

func cvDecodeComponentRefV2(wire []byte) (cvComponentRefV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentRefV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentRefV2Domain)) {
		return cvComponentRefV2{}, fmt.Errorf("invalid CV V2 component reference domain")
	}
	headerWire, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil {
		return cvComponentRefV2{}, fmt.Errorf("invalid CV V2 component reference header")
	}
	header, err := cvDecodeComponentHeaderV2(headerWire)
	if err != nil {
		return cvComponentRefV2{}, err
	}
	lockWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return cvComponentRefV2{}, fmt.Errorf("invalid CV V2 component reference lock")
	}
	lock, err := cvDecodeAPDBLockV2(lockWire)
	if err != nil {
		return cvComponentRefV2{}, err
	}
	ref := cvComponentRefV2{Header: header, Lock: *lock}
	canonical, err := cvComponentRefV2CanonicalBytes(ref)
	if err != nil || !bytes.Equal(canonical, wire) {
		return cvComponentRefV2{}, fmt.Errorf("non-canonical CV V2 component reference")
	}
	return ref, nil
}

func cvValidateComponentRefV2(ref cvComponentRefV2, apdbSigner *tblsThresholdSigner) error {
	if _, err := cvComponentRefV2CanonicalBytes(ref); err != nil {
		return err
	}
	if apdbSigner != nil {
		return cvVerifyAPDBLockV2(&ref.Lock, apdbSigner)
	}
	return nil
}

func cvPoolV2CanonicalBytes(pool *cvPoolV2, params cvV2Params) ([]byte, error) {
	if pool == nil || len(pool.ContextDigest) != 32 || pool.ProposerID < 0 ||
		len(pool.Components) != params.poolSize || len(pool.Digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool")
	}
	var unsigned bytes.Buffer
	_ = cvWriteBytes(&unsigned, []byte(cvPoolV2Domain))
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
		refWire, err := cvComponentRefV2CanonicalBytes(ref)
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&unsigned, refWire)
		lastDealer = ref.Header.DealerID
	}
	wantDigest := hashBytes([]byte(cvPoolDigestV2Domain), unsigned.Bytes())
	if !bytes.Equal(pool.Digest, wantDigest) {
		return nil, fmt.Errorf("CV V2 pool digest mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, unsigned.Bytes())
	_ = cvWriteBytes(&wire, pool.Digest)
	return wire.Bytes(), nil
}

func cvBuildPoolV2(contextDigest []byte, proposerID int, components []cvComponentRefV2, params cvV2Params) (*cvPoolV2, error) {
	pool := &cvPoolV2{ContextDigest: append([]byte(nil), contextDigest...), ProposerID: proposerID,
		Components: append([]cvComponentRefV2(nil), components...)}
	if len(pool.ContextDigest) != 32 || len(pool.Components) != params.poolSize {
		return nil, fmt.Errorf("invalid CV V2 pool construction")
	}
	var unsigned bytes.Buffer
	_ = cvWriteBytes(&unsigned, []byte(cvPoolV2Domain))
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
		refWire, err := cvComponentRefV2CanonicalBytes(ref)
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&unsigned, refWire)
		lastDealer = ref.Header.DealerID
	}
	pool.Digest = hashBytes([]byte(cvPoolDigestV2Domain), unsigned.Bytes())
	if _, err := cvPoolV2CanonicalBytes(pool, params); err != nil {
		return nil, err
	}
	return pool, nil
}

func cvDecodePoolV2(wire []byte, params cvV2Params) (*cvPoolV2, error) {
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
	domain, err := unsigned.bytes(len(cvPoolV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolV2Domain)) {
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
	components := make([]cvComponentRefV2, count)
	for i := range components {
		refWire, readErr := unsigned.bytes(cvMaxNetworkPayloadBytes)
		if readErr != nil {
			return nil, fmt.Errorf("invalid CV V2 pool component")
		}
		components[i], readErr = cvDecodeComponentRefV2(refWire)
		if readErr != nil {
			return nil, readErr
		}
	}
	if unsigned.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 pool unsigned suffix")
	}
	pool := &cvPoolV2{ContextDigest: context, ProposerID: int(proposer), Components: components, Digest: digest}
	canonical, err := cvPoolV2CanonicalBytes(pool, params)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool")
	}
	return pool, nil
}

func cvPoolCertificateV2CanonicalBytes(certificate *cvPoolCertificateV2) ([]byte, error) {
	if certificate == nil || len(certificate.PoolDigest) != 32 || len(certificate.Certificate) == 0 ||
		len(certificate.Certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 pool certificate")
	}
	if len(certificate.canonicalWire) != 0 {
		return certificate.canonicalWire, nil
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvPoolCertV2Domain))
	_ = cvWriteBytes(&wire, certificate.PoolDigest)
	_ = cvWriteBytes(&wire, certificate.Certificate)
	return wire.Bytes(), nil
}

func cvDecodePoolCertificateV2(wire []byte) (*cvPoolCertificateV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvPoolCertV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvPoolCertV2Domain)) {
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
	certificate := &cvPoolCertificateV2{PoolDigest: digest, Certificate: certificateWire}
	canonical, err := cvPoolCertificateV2CanonicalBytes(certificate)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 pool certificate")
	}
	certificate.canonicalWire = canonical
	return certificate, nil
}

func cvPoolCertificateStatementV2(contextDigest []byte, proposerID int, poolDigest []byte) ([]byte, error) {
	if len(contextDigest) != 32 || proposerID < 0 || len(poolDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 pool certificate statement")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(proposerID))
	_ = cvWriteBytes(&wire, poolDigest)
	return hashBytes([]byte(cvPoolCertV2Domain), wire.Bytes()), nil
}

func cvVerifyPoolCertificateV2(pool *cvPoolV2, certificate *cvPoolCertificateV2, controlSigner *tblsThresholdSigner) error {
	if pool == nil || certificate == nil || !cvV2SignerHasRole(controlSigner, cvV2RoleControl) || !bytes.Equal(pool.Digest, certificate.PoolDigest) {
		return fmt.Errorf("invalid CV V2 pool certificate")
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil || !controlSigner.VerifyRecovered(cvPoolCertV2Domain, statement, certificate.Certificate) {
		return fmt.Errorf("invalid CV V2 pool certificate signature")
	}
	return nil
}

func (state *cvPoolSlotStateV2) observePool(pool *cvPoolV2) error {
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

func (state *cvPoolSlotStateV2) markSigned(poolDigest []byte) error {
	if state == nil || !state.poolSeen || !bytes.Equal(state.poolDigest, poolDigest) || state.signed {
		return fmt.Errorf("invalid CV V2 pool slot signature transition")
	}
	state.signed = true
	return nil
}

func (state *cvPoolSlotStateV2) observeCertificate(certificate *cvPoolCertificateV2) error {
	if state == nil || !state.poolSeen || certificate == nil || !bytes.Equal(state.poolDigest, certificate.PoolDigest) {
		return fmt.Errorf("conflicting CV V2 pool certificate for proposer slot")
	}
	state.certSeen = true
	return nil
}
