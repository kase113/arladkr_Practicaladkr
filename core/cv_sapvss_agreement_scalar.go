package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	cvAgreementObjectScalarDomain        = "ARL-CV-sAPVSS/v2-scalar-group/agreement-object"
	cvAgreementObjectScalarCompactDomain = "ARL-CV-sAPVSS/v2-scalar-group/agreement-object/compact-v1"
	cvMaxAgreementObjectScalarBytes      = cvMaxNetworkPayloadBytes
)

type cvAgreementObjectScalar struct {
	Header          cvAggregateHeaderScalar
	Pool            cvPoolScalar
	PoolCert        cvPoolCertificateScalar
	ContributorCoin cvCoinOutputScalar
	SelectedIndices []int
	VCert           cvValidationCertificateScalar
	ARC             cvAPDBLockScalar
	// canonicalWire caches bytes accepted by the strict decoder.
	canonicalWire []byte
}

type cvAgreementPublicContextScalar struct {
	SID             string
	Epoch           uint64
	ContextDigest   []byte
	OldCommittee    []int
	EligibilityCoin *cvCoinOutputScalar
	Params          cvScalarParams
	APDBSigner      *tblsThresholdSigner
	ControlSigner   *tblsThresholdSigner
	CoinSigner      *tblsThresholdSigner
	ValidatorKeys   *cvValidatorKeyMaterialScalar
	// These fields are populated only by the epoch service after it verifies
	// the eligibility coin and derives both samples. Reference and test callers
	// leave them empty and retain the full public verification path.
	verifiedProposerSample  []int
	verifiedValidatorSample []int
	eligibilityVerified     bool
	verifiedCandidate       func([]byte) bool
}

func cvAgreementObjectScalarCanonicalBytes(object *cvAgreementObjectScalar, params cvScalarParams, validatorSample []int) ([]byte, error) {
	if object == nil || len(object.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 agreement object")
	}
	headerWire, err := cvAggregateHeaderScalarCanonicalBytes(&object.Header)
	if err != nil {
		return nil, err
	}
	poolWire, err := cvPoolScalarCanonicalBytes(&object.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCertWire, err := cvPoolCertificateScalarCanonicalBytes(&object.PoolCert)
	if err != nil {
		return nil, err
	}
	coinWire, err := cvCoinOutputScalarCanonicalBytes(&object.ContributorCoin)
	if err != nil {
		return nil, err
	}
	vCertWire, err := cvValidationCertificateScalarCanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := cvAPDBLockScalarCanonicalBytes(&object.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAgreementObjectScalarDomain))
	for _, nested := range [][]byte{headerWire, poolWire, poolCertWire, coinWire} {
		_ = cvWriteBytes(&wire, nested)
	}
	_ = cvWriteUint32(&wire, len(object.SelectedIndices))
	for _, index := range object.SelectedIndices {
		if index < 0 || index >= params.poolSize {
			return nil, fmt.Errorf("invalid CV V2 selected pool index")
		}
		cvWriteUint64(&wire, uint64(index))
	}
	_ = cvWriteBytes(&wire, vCertWire)
	_ = cvWriteBytes(&wire, arcWire)
	if wire.Len() > cvMaxAgreementObjectScalarBytes {
		return nil, fmt.Errorf("CV V2 agreement object exceeds wire limit")
	}
	return wire.Bytes(), nil
}

// cvAgreementObjectScalarWireMode selects the network representation. The logical
// object and its predicate remain unchanged; full-v1 is retained for mixed
// deployments and compatibility troubleshooting.
func cvAgreementObjectScalarWireMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_AGREEMENT_WIRE"))) {
	case "full", "full-v1":
		return "full-v1"
	case "compact", "compact-v1":
		return "compact-v1"
	default:
		return "compact-v1"
	}
}

func cvAgreementObjectScalarWireBytes(object *cvAgreementObjectScalar, params cvScalarParams, validatorSample []int) ([]byte, error) {
	if cvAgreementObjectScalarWireMode() == "full-v1" {
		return cvAgreementObjectScalarCanonicalBytes(object, params, validatorSample)
	}
	return cvAgreementObjectScalarCompactCanonicalBytes(object, params, validatorSample)
}

// cvAgreementObjectScalarCompactCanonicalBytes changes only outer framing and
// selection encoding; decoding still materializes the full logical object.
func cvAgreementObjectScalarCompactCanonicalBytes(object *cvAgreementObjectScalar, params cvScalarParams, validatorSample []int) ([]byte, error) {
	if object == nil || len(object.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid compact CV V2 agreement object")
	}
	header, err := cvAggregateHeaderScalarCanonicalBytes(&object.Header)
	if err != nil {
		return nil, err
	}
	pool, err := cvPoolScalarCanonicalBytes(&object.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvPoolCertificateScalarCanonicalBytes(&object.PoolCert)
	if err != nil {
		return nil, err
	}
	coin, err := cvCoinOutputScalarCanonicalBytes(&object.ContributorCoin)
	if err != nil {
		return nil, err
	}
	vCert, err := cvValidationCertificateScalarCanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return nil, err
	}
	arc, err := cvAPDBLockScalarCanonicalBytes(&object.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAgreementObjectScalarCompactDomain))
	for _, nested := range [][]byte{header, pool, poolCert, coin} {
		_ = cvWriteBytes(&wire, nested)
	}
	_ = cvWriteUint32(&wire, len(object.SelectedIndices))
	var previous int64
	for i, index := range object.SelectedIndices {
		if index < 0 || index >= params.poolSize {
			return nil, fmt.Errorf("invalid compact CV V2 selected index")
		}
		value := uint64(index)
		if i > 0 {
			delta := int64(index) - previous
			value = uint64(delta<<1) ^ uint64(delta>>63)
		}
		var encoded [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(encoded[:], value)
		_, _ = wire.Write(encoded[:n])
		previous = int64(index)
	}
	_ = cvWriteBytes(&wire, vCert)
	_ = cvWriteBytes(&wire, arc)
	if wire.Len() > cvMaxAgreementObjectScalarBytes {
		return nil, fmt.Errorf("compact CV V2 agreement object exceeds wire limit")
	}
	return wire.Bytes(), nil
}

func cvDecodeAgreementObjectScalar(wire []byte, params cvScalarParams, validatorSample []int) (*cvAgreementObjectScalar, error) {
	if len(wire) == 0 || len(wire) > cvMaxAgreementObjectScalarBytes {
		return nil, fmt.Errorf("invalid CV V2 agreement object wire size")
	}
	compactPrefix := len(cvAgreementObjectScalarCompactDomain) + 4
	if len(wire) >= compactPrefix && bytes.Equal(wire[4:compactPrefix], []byte(cvAgreementObjectScalarCompactDomain)) {
		return cvDecodeAgreementObjectScalarCompact(wire, params, validatorSample)
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAgreementObjectScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAgreementObjectScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 agreement object domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxAgreementObjectScalarBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 agreement object field")
		}
	}
	header, err := cvDecodeAggregateHeaderScalar(nested[0])
	if err != nil {
		return nil, err
	}
	pool, err := cvDecodePoolScalar(nested[1], params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvDecodePoolCertificateScalar(nested[2])
	if err != nil {
		return nil, err
	}
	coin, err := cvDecodeCoinOutputScalar(nested[3])
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 agreement selection count")
	}
	selected := make([]int, count)
	for i := range selected {
		value, readErr := r.uint64()
		if readErr != nil || value >= uint64(params.poolSize) {
			return nil, fmt.Errorf("invalid CV V2 agreement selected index")
		}
		selected[i] = int(value)
	}
	vCertWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 agreement VCert")
	}
	vCert, err := cvDecodeValidationCertificateScalar(vCertWire, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 agreement ARC")
	}
	arc, err := cvDecodeAPDBLockScalar(arcWire)
	if err != nil {
		return nil, err
	}
	object := &cvAgreementObjectScalar{Header: *header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *coin,
		SelectedIndices: selected, VCert: *vCert, ARC: *arc}
	canonical, err := cvAgreementObjectScalarCanonicalBytes(object, params, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 agreement object")
	}
	object.canonicalWire = canonical
	return object, nil
}

func cvDecodeAgreementObjectScalarCompact(wire []byte, params cvScalarParams, validatorSample []int) (*cvAgreementObjectScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAgreementObjectScalarCompactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAgreementObjectScalarCompactDomain)) {
		return nil, fmt.Errorf("invalid compact CV V2 agreement domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxAgreementObjectScalarBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid compact CV V2 agreement field")
		}
	}
	header, err := cvDecodeAggregateHeaderScalar(nested[0])
	if err != nil {
		return nil, err
	}
	pool, err := cvDecodePoolScalar(nested[1], params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvDecodePoolCertificateScalar(nested[2])
	if err != nil {
		return nil, err
	}
	coin, err := cvDecodeCoinOutputScalar(nested[3])
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != params.componentCount {
		return nil, fmt.Errorf("invalid compact CV V2 selection count")
	}
	selected := make([]int, count)
	var previous int64
	for i := range selected {
		value, readErr := binary.ReadUvarint(r.reader)
		if readErr != nil {
			return nil, fmt.Errorf("invalid compact CV V2 selected delta")
		}
		current := int64(value)
		if i > 0 {
			delta := int64(value >> 1)
			if value&1 != 0 {
				delta = ^delta
			}
			current = previous + delta
		}
		if current < 0 || current >= int64(params.poolSize) {
			return nil, fmt.Errorf("invalid compact CV V2 selected index")
		}
		selected[i], previous = int(current), current
	}
	vCertWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil {
		return nil, fmt.Errorf("invalid compact CV V2 VCert")
	}
	vCert, err := cvDecodeValidationCertificateScalar(vCertWire, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV V2 ARC")
	}
	arc, err := cvDecodeAPDBLockScalar(arcWire)
	if err != nil {
		return nil, err
	}
	object := &cvAgreementObjectScalar{Header: *header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *coin, SelectedIndices: selected, VCert: *vCert, ARC: *arc}
	canonical, err := cvAgreementObjectScalarCompactCanonicalBytes(object, params, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV V2 agreement object")
	}
	object.canonicalWire = canonical
	return object, nil
}

// cvVerifyAgreementObjectScalar is the public MVBA predicate core. It deliberately
// has no APDB store, component cache, recovery callback, or mutable slot state.
func cvVerifyAgreementObjectScalar(object *cvAgreementObjectScalar, public cvAgreementPublicContextScalar) error {
	_, err := cvValidateAgreementObjectScalar(object, public)
	return err
}

func cvValidateAgreementObjectScalar(
	object *cvAgreementObjectScalar, public cvAgreementPublicContextScalar,
) ([]byte, error) {
	var proposers, validators []int
	var err error
	if public.eligibilityVerified {
		if len(public.verifiedProposerSample) != public.Params.proposerSampleSize ||
			len(public.verifiedValidatorSample) != public.Params.validatorSampleSize ||
			!cvValidValidatorSampleScalar(public.verifiedValidatorSample, public.ValidatorKeys) {
			return nil, fmt.Errorf("invalid cached CV V2 agreement eligibility samples")
		}
		// The epoch service owns these snapshots and never mutates them after
		// publication; avoid allocating copies on every candidate predicate.
		proposers = public.verifiedProposerSample
		validators = public.verifiedValidatorSample
	} else {
		proposers, validators, err = cvAgreementEligibilitySamplesScalar(public)
	}
	if object == nil || err != nil || len(public.ContextDigest) != 32 || !cvScalarSignerHasRole(public.APDBSigner, cvScalarRoleAPDB) ||
		!cvScalarSignerHasRole(public.ControlSigner, cvScalarRoleControl) || !cvScalarSignerHasRole(public.CoinSigner, cvScalarRoleCoin) || public.ValidatorKeys == nil {
		return nil, fmt.Errorf("invalid CV V2 agreement public context")
	}
	canonical := object.canonicalWire
	if len(canonical) == 0 {
		canonical, err = cvAgreementObjectScalarWireBytes(object, public.Params, validators)
		if err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(object.Header.ContextDigest, public.ContextDigest) || !bytes.Equal(object.Pool.ContextDigest, public.ContextDigest) ||
		object.Header.ProposerID != object.Pool.ProposerID || !cvContainsID(proposers, object.Header.ProposerID) {
		return nil, fmt.Errorf("invalid CV V2 agreement proposer or context")
	}
	if !bytes.Equal(object.Header.PoolDigest, object.Pool.Digest) {
		return nil, fmt.Errorf("CV V2 agreement pool/header mismatch")
	}
	for i := range object.Pool.Components {
		if err := cvValidateComponentRefScalar(object.Pool.Components[i], public.APDBSigner); err != nil {
			return nil, fmt.Errorf("invalid CV V2 agreement component lock: %w", err)
		}
	}
	if err := cvVerifyPoolCertificateScalar(&object.Pool, &object.PoolCert, public.ControlSigner); err != nil {
		return nil, err
	}
	expectedInvocation, err := cvContributorCoinInvocationScalar(public.ContextDigest, object.Header.ProposerID, object.Pool.Digest)
	if err != nil || cvVerifyCoinOutputScalar(&object.ContributorCoin, expectedInvocation, public.CoinSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 agreement contributor coin")
	}
	wantSelection, err := cvSelectedPoolIndicesScalar(public.Params.poolSize, public.Params.componentCount, object.ContributorCoin.Value)
	if err != nil || !equalInts(wantSelection, object.SelectedIndices) {
		return nil, fmt.Errorf("invalid CV V2 agreement contributor selection")
	}
	selectionDigest, err := cvSelectionDigestScalar(&object.ContributorCoin, object.SelectedIndices, public.Params.poolSize, public.Params.componentCount)
	if err != nil || !bytes.Equal(selectionDigest, object.Header.SelectionDigest) {
		return nil, fmt.Errorf("invalid CV V2 agreement selection digest")
	}
	if err := cvVerifyValidationCertificateScalar(&object.VCert, &object.Header, validators, public.Params.validatorThreshold, public.ValidatorKeys); err != nil {
		return nil, err
	}
	if !bytes.Equal(object.ARC.InstanceDigest, object.Header.APDBInstance) || !bytes.Equal(object.ARC.Root, object.Header.APDBRoot) {
		return nil, fmt.Errorf("CV V2 agreement ARC/header mismatch")
	}
	if err := cvVerifyAPDBLockScalar(&object.ARC, public.APDBSigner); err != nil {
		return nil, err
	}
	return canonical, nil
}

func cvAggregatePredicateScalar(public cvAgreementPublicContextScalar) func(int, []byte) bool {
	var verified sync.Map
	return func(_ int, candidate []byte) bool {
		key := string(candidate)
		if _, ok := verified.Load(key); ok {
			return true
		}
		if public.verifiedCandidate != nil && public.verifiedCandidate(candidate) {
			verified.Store(key, struct{}{})
			return true
		}
		_, validators, err := cvAgreementEligibilitySamplesScalar(public)
		if err != nil {
			return false
		}
		object, err := cvDecodeAgreementObjectScalar(candidate, public.Params, validators)
		if err != nil || cvVerifyAgreementObjectScalar(object, public) != nil {
			return false
		}
		verified.Store(key, struct{}{})
		return true
	}
}

func cvAgreementEligibilitySamplesScalar(public cvAgreementPublicContextScalar) ([]int, []int, error) {
	if public.eligibilityVerified {
		if len(public.verifiedProposerSample) != public.Params.proposerSampleSize ||
			len(public.verifiedValidatorSample) != public.Params.validatorSampleSize ||
			!cvValidValidatorSampleScalar(public.verifiedValidatorSample, public.ValidatorKeys) {
			return nil, nil, fmt.Errorf("invalid cached CV V2 agreement eligibility samples")
		}
		return append([]int(nil), public.verifiedProposerSample...),
			append([]int(nil), public.verifiedValidatorSample...), nil
	}
	if public.SID == "" || public.Epoch == 0 || public.EligibilityCoin == nil || public.CoinSigner == nil ||
		len(public.OldCommittee) == 0 || !equalInts(public.OldCommittee, sortedUnique(public.OldCommittee)) {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility context")
	}
	expectedInvocation, err := cvEligibilityCoinInvocationScalar(public.SID, public.Epoch)
	if err != nil || cvVerifyCoinOutputScalar(public.EligibilityCoin, expectedInvocation, public.CoinSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesScalar(
		public.OldCommittee, public.EligibilityCoin.Value, public.Params.proposerSampleSize, public.Params.validatorSampleSize,
	)
	if err != nil || !cvValidValidatorSampleScalar(validators, public.ValidatorKeys) {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility samples")
	}
	return proposers, validators, nil
}

func cvContainsID(ids []int, target int) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
