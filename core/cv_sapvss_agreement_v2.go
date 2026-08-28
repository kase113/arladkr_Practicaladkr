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
	cvAgreementObjectV2Domain        = "ARL-CV-sAPVSS/v2-scalar-group/agreement-object"
	cvAgreementObjectV2CompactDomain = "ARL-CV-sAPVSS/v2-scalar-group/agreement-object/compact-v1"
	cvMaxAgreementObjectV2Bytes      = cvMaxNetworkPayloadBytes
)

type cvAgreementObjectV2 struct {
	Header          cvAggregateHeaderV2
	Pool            cvPoolV2
	PoolCert        cvPoolCertificateV2
	ContributorCoin cvCoinOutputV2
	SelectedIndices []int
	VCert           cvValidationCertificateV2
	ARC             cvAPDBLockV2
	// canonicalWire is populated only by the strict decoder after it has
	// compared the re-encoded object with the received wire. It avoids a
	// second identical encode when the object immediately enters the public
	// predicate; manually constructed objects leave it empty.
	canonicalWire []byte
}

type cvAgreementPublicContextV2 struct {
	SID             string
	Epoch           uint64
	ContextDigest   []byte
	OldCommittee    []int
	EligibilityCoin *cvCoinOutputV2
	Params          cvV2Params
	APDBSigner      *tblsThresholdSigner
	ControlSigner   *tblsThresholdSigner
	CoinSigner      *tblsThresholdSigner
	ValidatorKeys   *cvValidatorKeyMaterialV2
	// These fields are populated only by the epoch service after it verifies
	// the eligibility coin and derives both samples. Reference and test callers
	// leave them empty and retain the full public verification path.
	verifiedProposerSample  []int
	verifiedValidatorSample []int
	eligibilityVerified     bool
	verifiedCandidate       func([]byte) bool
}

func cvAgreementObjectV2CanonicalBytes(object *cvAgreementObjectV2, params cvV2Params, validatorSample []int) ([]byte, error) {
	if object == nil || len(object.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 agreement object")
	}
	headerWire, err := cvAggregateHeaderV2CanonicalBytes(&object.Header)
	if err != nil {
		return nil, err
	}
	poolWire, err := cvPoolV2CanonicalBytes(&object.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCertWire, err := cvPoolCertificateV2CanonicalBytes(&object.PoolCert)
	if err != nil {
		return nil, err
	}
	coinWire, err := cvCoinOutputV2CanonicalBytes(&object.ContributorCoin)
	if err != nil {
		return nil, err
	}
	vCertWire, err := cvValidationCertificateV2CanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := cvAPDBLockV2CanonicalBytes(&object.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAgreementObjectV2Domain))
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
	if wire.Len() > cvMaxAgreementObjectV2Bytes {
		return nil, fmt.Errorf("CV V2 agreement object exceeds wire limit")
	}
	return wire.Bytes(), nil
}

// cvAgreementObjectV2WireMode selects the network representation. The logical
// object and its predicate remain unchanged; full-v1 is retained for mixed
// deployments and compatibility troubleshooting.
func cvAgreementObjectV2WireMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_AGREEMENT_WIRE"))) {
	case "full", "full-v1":
		return "full-v1"
	case "compact", "compact-v1":
		return "compact-v1"
	default:
		return "compact-v1"
	}
}

func cvAgreementObjectV2WireBytes(object *cvAgreementObjectV2, params cvV2Params, validatorSample []int) ([]byte, error) {
	if cvAgreementObjectV2WireMode() == "full-v1" {
		return cvAgreementObjectV2CanonicalBytes(object, params, validatorSample)
	}
	return cvAgreementObjectV2CompactCanonicalBytes(object, params, validatorSample)
}

// cvAgreementObjectV2CompactCanonicalBytes keeps the same four authenticated
// nested fields as full-v1 and changes only the outer framing plus selection
// encoding. This is deliberately conservative: decoding materializes the
// original object before the existing full predicate runs.
func cvAgreementObjectV2CompactCanonicalBytes(object *cvAgreementObjectV2, params cvV2Params, validatorSample []int) ([]byte, error) {
	if object == nil || len(object.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid compact CV V2 agreement object")
	}
	header, err := cvAggregateHeaderV2CanonicalBytes(&object.Header)
	if err != nil {
		return nil, err
	}
	pool, err := cvPoolV2CanonicalBytes(&object.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvPoolCertificateV2CanonicalBytes(&object.PoolCert)
	if err != nil {
		return nil, err
	}
	coin, err := cvCoinOutputV2CanonicalBytes(&object.ContributorCoin)
	if err != nil {
		return nil, err
	}
	vCert, err := cvValidationCertificateV2CanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return nil, err
	}
	arc, err := cvAPDBLockV2CanonicalBytes(&object.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAgreementObjectV2CompactDomain))
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
	if wire.Len() > cvMaxAgreementObjectV2Bytes {
		return nil, fmt.Errorf("compact CV V2 agreement object exceeds wire limit")
	}
	return wire.Bytes(), nil
}

func cvDecodeAgreementObjectV2(wire []byte, params cvV2Params, validatorSample []int) (*cvAgreementObjectV2, error) {
	if len(wire) == 0 || len(wire) > cvMaxAgreementObjectV2Bytes {
		return nil, fmt.Errorf("invalid CV V2 agreement object wire size")
	}
	compactPrefix := len(cvAgreementObjectV2CompactDomain) + 4
	if len(wire) >= compactPrefix && bytes.Equal(wire[4:compactPrefix], []byte(cvAgreementObjectV2CompactDomain)) {
		return cvDecodeAgreementObjectV2Compact(wire, params, validatorSample)
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAgreementObjectV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvAgreementObjectV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 agreement object domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxAgreementObjectV2Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 agreement object field")
		}
	}
	header, err := cvDecodeAggregateHeaderV2(nested[0])
	if err != nil {
		return nil, err
	}
	pool, err := cvDecodePoolV2(nested[1], params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvDecodePoolCertificateV2(nested[2])
	if err != nil {
		return nil, err
	}
	coin, err := cvDecodeCoinOutputV2(nested[3])
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
	vCert, err := cvDecodeValidationCertificateV2(vCertWire, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 agreement ARC")
	}
	arc, err := cvDecodeAPDBLockV2(arcWire)
	if err != nil {
		return nil, err
	}
	object := &cvAgreementObjectV2{Header: *header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *coin,
		SelectedIndices: selected, VCert: *vCert, ARC: *arc}
	canonical, err := cvAgreementObjectV2CanonicalBytes(object, params, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 agreement object")
	}
	object.canonicalWire = canonical
	return object, nil
}

func cvDecodeAgreementObjectV2Compact(wire []byte, params cvV2Params, validatorSample []int) (*cvAgreementObjectV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAgreementObjectV2CompactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAgreementObjectV2CompactDomain)) {
		return nil, fmt.Errorf("invalid compact CV V2 agreement domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxAgreementObjectV2Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid compact CV V2 agreement field")
		}
	}
	header, err := cvDecodeAggregateHeaderV2(nested[0])
	if err != nil {
		return nil, err
	}
	pool, err := cvDecodePoolV2(nested[1], params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvDecodePoolCertificateV2(nested[2])
	if err != nil {
		return nil, err
	}
	coin, err := cvDecodeCoinOutputV2(nested[3])
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
	vCert, err := cvDecodeValidationCertificateV2(vCertWire, validatorSample)
	if err != nil {
		return nil, err
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV V2 ARC")
	}
	arc, err := cvDecodeAPDBLockV2(arcWire)
	if err != nil {
		return nil, err
	}
	object := &cvAgreementObjectV2{Header: *header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *coin, SelectedIndices: selected, VCert: *vCert, ARC: *arc}
	canonical, err := cvAgreementObjectV2CompactCanonicalBytes(object, params, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV V2 agreement object")
	}
	object.canonicalWire = canonical
	return object, nil
}

// cvVerifyAgreementObjectV2 is the public MVBA predicate core. It deliberately
// has no APDB store, component cache, recovery callback, or mutable slot state.
func cvVerifyAgreementObjectV2(object *cvAgreementObjectV2, public cvAgreementPublicContextV2) error {
	_, err := cvValidateAgreementObjectV2(object, public)
	return err
}

func cvValidateAgreementObjectV2(
	object *cvAgreementObjectV2, public cvAgreementPublicContextV2,
) ([]byte, error) {
	var proposers, validators []int
	var err error
	if public.eligibilityVerified {
		if len(public.verifiedProposerSample) != public.Params.proposerSampleSize ||
			len(public.verifiedValidatorSample) != public.Params.validatorSampleSize ||
			!cvValidValidatorSampleV2(public.verifiedValidatorSample, public.ValidatorKeys) {
			return nil, fmt.Errorf("invalid cached CV V2 agreement eligibility samples")
		}
		// The epoch service owns these snapshots and never mutates them after
		// publication; avoid allocating copies on every candidate predicate.
		proposers = public.verifiedProposerSample
		validators = public.verifiedValidatorSample
	} else {
		proposers, validators, err = cvAgreementEligibilitySamplesV2(public)
	}
	if object == nil || err != nil || len(public.ContextDigest) != 32 || !cvV2SignerHasRole(public.APDBSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(public.ControlSigner, cvV2RoleControl) || !cvV2SignerHasRole(public.CoinSigner, cvV2RoleCoin) || public.ValidatorKeys == nil {
		return nil, fmt.Errorf("invalid CV V2 agreement public context")
	}
	canonical := object.canonicalWire
	if len(canonical) == 0 {
		canonical, err = cvAgreementObjectV2WireBytes(object, public.Params, validators)
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
		if err := cvValidateComponentRefV2(object.Pool.Components[i], public.APDBSigner); err != nil {
			return nil, fmt.Errorf("invalid CV V2 agreement component lock: %w", err)
		}
	}
	if err := cvVerifyPoolCertificateV2(&object.Pool, &object.PoolCert, public.ControlSigner); err != nil {
		return nil, err
	}
	expectedInvocation, err := cvContributorCoinInvocationV2(public.ContextDigest, object.Header.ProposerID, object.Pool.Digest)
	if err != nil || cvVerifyCoinOutputV2(&object.ContributorCoin, expectedInvocation, public.CoinSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 agreement contributor coin")
	}
	wantSelection, err := cvSelectedPoolIndicesV2(public.Params.poolSize, public.Params.componentCount, object.ContributorCoin.Value)
	if err != nil || !equalInts(wantSelection, object.SelectedIndices) {
		return nil, fmt.Errorf("invalid CV V2 agreement contributor selection")
	}
	selectionDigest, err := cvSelectionDigestV2(&object.ContributorCoin, object.SelectedIndices, public.Params.poolSize, public.Params.componentCount)
	if err != nil || !bytes.Equal(selectionDigest, object.Header.SelectionDigest) {
		return nil, fmt.Errorf("invalid CV V2 agreement selection digest")
	}
	if err := cvVerifyValidationCertificateV2(&object.VCert, &object.Header, validators, public.Params.validatorThreshold, public.ValidatorKeys); err != nil {
		return nil, err
	}
	if !bytes.Equal(object.ARC.InstanceDigest, object.Header.APDBInstance) || !bytes.Equal(object.ARC.Root, object.Header.APDBRoot) {
		return nil, fmt.Errorf("CV V2 agreement ARC/header mismatch")
	}
	if err := cvVerifyAPDBLockV2(&object.ARC, public.APDBSigner); err != nil {
		return nil, err
	}
	return canonical, nil
}

func cvAggregatePredicateV2(public cvAgreementPublicContextV2) func(int, []byte) bool {
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
		_, validators, err := cvAgreementEligibilitySamplesV2(public)
		if err != nil {
			return false
		}
		object, err := cvDecodeAgreementObjectV2(candidate, public.Params, validators)
		if err != nil || cvVerifyAgreementObjectV2(object, public) != nil {
			return false
		}
		verified.Store(key, struct{}{})
		return true
	}
}

func cvAgreementEligibilitySamplesV2(public cvAgreementPublicContextV2) ([]int, []int, error) {
	if public.eligibilityVerified {
		if len(public.verifiedProposerSample) != public.Params.proposerSampleSize ||
			len(public.verifiedValidatorSample) != public.Params.validatorSampleSize ||
			!cvValidValidatorSampleV2(public.verifiedValidatorSample, public.ValidatorKeys) {
			return nil, nil, fmt.Errorf("invalid cached CV V2 agreement eligibility samples")
		}
		return append([]int(nil), public.verifiedProposerSample...),
			append([]int(nil), public.verifiedValidatorSample...), nil
	}
	if public.SID == "" || public.Epoch == 0 || public.EligibilityCoin == nil || public.CoinSigner == nil ||
		len(public.OldCommittee) == 0 || !equalInts(public.OldCommittee, sortedUnique(public.OldCommittee)) {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility context")
	}
	expectedInvocation, err := cvEligibilityCoinInvocationV2(public.SID, public.Epoch)
	if err != nil || cvVerifyCoinOutputV2(public.EligibilityCoin, expectedInvocation, public.CoinSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 agreement eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesV2(
		public.OldCommittee, public.EligibilityCoin.Value, public.Params.proposerSampleSize, public.Params.validatorSampleSize,
	)
	if err != nil || !cvValidValidatorSampleV2(validators, public.ValidatorKeys) {
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
