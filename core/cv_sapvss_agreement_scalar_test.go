package core

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestCVAgreementObjectScalarCompactRoundTripAndTamper(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	_, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := cvAgreementObjectScalarCompactCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	full, err := cvAgreementObjectScalarCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) >= len(full) {
		t.Fatalf("compact wire did not shrink: compact=%d full=%d", len(compact), len(full))
	}
	t.Logf("compact-v1 agreement bytes: compact=%d full=%d", len(compact), len(full))
	decoded, err := cvDecodeAgreementObjectScalar(compact, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyAgreementObjectScalar(decoded, public); err != nil {
		t.Fatalf("compact predicate rejected logical object: %v", err)
	}
	mutated := append([]byte(nil), compact...)
	mutated[len(mutated)-1] ^= 1
	if decodedMutated, err := cvDecodeAgreementObjectScalar(mutated, public.Params, validators); err == nil {
		if cvVerifyAgreementObjectScalar(decodedMutated, public) == nil {
			t.Fatal("compact predicate accepted tampered wire")
		}
	}
}

func TestCVAgreementObjectScalarCompactDeltaBoundaries(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	_, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	object.SelectedIndices = []int{0, 1, public.Params.poolSize - 1}
	wire, err := cvAgreementObjectScalarCompactCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAgreementObjectScalar(wire, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(decoded.SelectedIndices, object.SelectedIndices) {
		t.Fatalf("selection roundtrip: got %v want %v", decoded.SelectedIndices, object.SelectedIndices)
	}
}

func TestCVRunAgreementScalarRejectsInvalidCandidateBeforeNetwork(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	invalid := *object
	invalid.Header.AggregateDigest = append([]byte(nil), object.Header.AggregateDigest...)
	invalid.Header.AggregateDigest[0] ^= 1
	cfg := cvScalarParamsTestConfig()
	cfg.LocalNodeIDs = []int{cfg.OldCommittee[0]}
	if _, _, _, err := cvRunAgreementScalar(context.Background(), cfg, &invalid, public); err == nil {
		t.Fatal("CV V2 agreement entered network with an invalid local candidate")
	}
}

func cvRecoverThresholdCertificateScalarForTest(t *testing.T, signer *tblsThresholdSigner, members []int, domain string, digest []byte) []byte {
	t.Helper()
	shares := make(map[int][]byte, signer.Threshold())
	for _, member := range members[:signer.Threshold()] {
		share, err := signer.SignShare(member, domain, digest)
		if err != nil {
			t.Fatal(err)
		}
		shares[member] = share
	}
	certificate, err := signer.Recover(domain, digest, shares)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func cvAgreementObjectScalarFixture(t *testing.T) (*cvAgreementObjectScalar, cvAgreementPublicContextScalar) {
	t.Helper()
	cfg := cvScalarParamsTestConfig()
	params, err := cvDeriveScalarParams(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keyPublic := filepath.Join(t.TempDir(), "threshold-public")
	keySecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleScalar(keyPublic, keySecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleScalar(keyPublic, keySecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromScalarMaterial(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}
	validatorPublic := filepath.Join(t.TempDir(), "validator-public")
	validatorSecret := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryScalar(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	validatorKeys, err := cvLoadValidatorRegistryScalar(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	eligibilityInvocation, err := cvEligibilityCoinInvocationScalar(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	eligibilityDigest, err := cvCoinInvocationDigestScalar(eligibilityInvocation)
	if err != nil {
		t.Fatal(err)
	}
	eligibilityCertificate := cvRecoverThresholdCertificateScalarForTest(t, coinSigner, cfg.OldCommittee, cvScalarCoinDomain, eligibilityDigest)
	eligibilityCoin, err := cvBuildCoinOutputScalar(eligibilityInvocation, eligibilityCertificate, coinSigner)
	if err != nil {
		t.Fatal(err)
	}
	proposers, validatorSample, err := cvDeriveEligibilitySamplesScalar(cfg.OldCommittee, eligibilityCoin.Value, params.proposerSampleSize, params.validatorSampleSize)
	if err != nil {
		t.Fatal(err)
	}
	proposer := proposers[0]

	contextDigest := hashBytes([]byte("agreement V2 context"))
	components := cvPoolScalarTestComponents(t, contextDigest, params)
	for i := range components {
		statement, err := cvAPDBStoredStatementScalar(components[i].Lock.InstanceDigest, components[i].Lock.Root)
		if err != nil {
			t.Fatal(err)
		}
		components[i].Lock.Certificate = cvRecoverThresholdCertificateScalarForTest(t, apdbSigner, cfg.OldCommittee, cvAPDBStoredDomain, statement)
	}
	pool, err := cvBuildPoolScalar(contextDigest, proposer, components, params)
	if err != nil {
		t.Fatal(err)
	}
	poolStatement, err := cvPoolCertificateStatementScalar(contextDigest, proposer, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	poolCert := cvPoolCertificateScalar{PoolDigest: append([]byte(nil), pool.Digest...),
		Certificate: cvRecoverThresholdCertificateScalarForTest(t, controlSigner, cfg.OldCommittee, cvPoolCertScalarDomain, poolStatement)}

	invocation, err := cvContributorCoinInvocationScalar(contextDigest, proposer, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	coinDigest, err := cvCoinInvocationDigestScalar(invocation)
	if err != nil {
		t.Fatal(err)
	}
	coinCertificate := cvRecoverThresholdCertificateScalarForTest(t, coinSigner, cfg.OldCommittee, cvScalarCoinDomain, coinDigest)
	coin, err := cvBuildCoinOutputScalar(invocation, coinCertificate, coinSigner)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := cvSelectedPoolIndicesScalar(params.poolSize, params.componentCount, coin.Value)
	if err != nil {
		t.Fatal(err)
	}
	selectionDigest, err := cvSelectionDigestScalar(coin, selected, params.poolSize, params.componentCount)
	if err != nil {
		t.Fatal(err)
	}
	aggregateRoot := hashBytes([]byte("agreement V2 aggregate root"))
	aggregateInstance, err := cvAggregateInstanceDigestScalar(contextDigest, proposer, pool.Digest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	header := cvAggregateHeaderScalar{ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
		SelectionDigest: selectionDigest, AggregateDigest: hashBytes([]byte("agreement V2 aggregate")),
		PayloadDigest: hashBytes([]byte("agreement V2 payload")), APDBInstance: aggregateInstance, APDBRoot: aggregateRoot}
	arcStatement, err := cvAPDBStoredStatementScalar(aggregateInstance, aggregateRoot)
	if err != nil {
		t.Fatal(err)
	}
	arc := cvAPDBLockScalar{InstanceDigest: append([]byte(nil), aggregateInstance...), Root: append([]byte(nil), aggregateRoot...),
		Certificate: cvRecoverThresholdCertificateScalarForTest(t, apdbSigner, cfg.OldCommittee, cvAPDBStoredDomain, arcStatement)}
	votes := make(map[int][]byte, params.validatorThreshold)
	for _, member := range validatorSample[:params.validatorThreshold] {
		votes[member], err = cvSignValidationScalar(member, &header, validatorSample, validatorKeys)
		if err != nil {
			t.Fatal(err)
		}
	}
	vCert, err := cvBuildValidationCertificateScalar(&header, validatorSample, params.validatorThreshold, votes, validatorKeys)
	if err != nil {
		t.Fatal(err)
	}
	object := &cvAgreementObjectScalar{Header: header, Pool: *pool, PoolCert: poolCert, ContributorCoin: *coin,
		SelectedIndices: selected, VCert: *vCert, ARC: arc}
	public := cvAgreementPublicContextScalar{SID: cfg.SID, Epoch: uint64(cfg.Epoch), ContextDigest: contextDigest,
		OldCommittee: append([]int(nil), cfg.OldCommittee...), EligibilityCoin: eligibilityCoin, Params: params,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner, ValidatorKeys: validatorKeys}
	return object, public
}

func TestCVAgreementObjectScalarPublicPredicateAndCodec(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	if err := cvVerifyAgreementObjectScalar(object, public); err != nil {
		t.Fatalf("verify V2 agreement object: %v", err)
	}
	_, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectScalarCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAgreementObjectScalar(wire, public.Params, validators)
	if err != nil || !bytes.Equal(decoded.Header.APDBInstance, object.Header.APDBInstance) {
		t.Fatalf("V2 agreement object codec: %v", err)
	}
	predicate := cvAggregatePredicateScalar(public)
	if !predicate(0, wire) {
		t.Fatal("public predicate rejected valid V2 agreement object")
	}
	if predicate(0, append(append([]byte(nil), wire...), 0)) {
		t.Fatal("public predicate accepted trailing agreement bytes")
	}
}

func TestCVAgreementObjectScalarPredicateRejectsPublicBindingMutations(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	badSelection := *object
	badSelection.SelectedIndices = append([]int(nil), object.SelectedIndices...)
	badSelection.SelectedIndices[0], badSelection.SelectedIndices[1] = badSelection.SelectedIndices[1], badSelection.SelectedIndices[0]
	if err := cvVerifyAgreementObjectScalar(&badSelection, public); err == nil {
		t.Fatal("accepted reordered contributor selection")
	}
	badARC := *object
	badARC.ARC = object.ARC
	badARC.ARC.Root = append([]byte(nil), object.ARC.Root...)
	badARC.ARC.Root[0] ^= 1
	if err := cvVerifyAgreementObjectScalar(&badARC, public); err == nil {
		t.Fatal("accepted ARC/header root mismatch")
	}
	wrongEligibility := public
	wrongEligibility.SID += "-wrong"
	if err := cvVerifyAgreementObjectScalar(object, wrongEligibility); err == nil {
		t.Fatal("accepted ineligible V2 proposer")
	}
	badVCert := *object
	badVCert.VCert = object.VCert
	badVCert.VCert.AggregateSignature = append([]byte(nil), object.VCert.AggregateSignature...)
	badVCert.VCert.AggregateSignature[len(badVCert.VCert.AggregateSignature)-1] ^= 1
	if err := cvVerifyAgreementObjectScalar(&badVCert, public); err == nil {
		t.Fatal("accepted invalid VCert")
	}
}

func TestCVAgreementObjectScalarRejectsThresholdSignerRoleSwaps(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)

	swappedLocks := public
	swappedLocks.APDBSigner, swappedLocks.ControlSigner = public.ControlSigner, public.APDBSigner
	if err := cvVerifyAgreementObjectScalar(object, swappedLocks); err == nil {
		t.Fatal("accepted swapped APDB and control signers")
	}

	wrongCoin := public
	wrongCoin.CoinSigner = public.ControlSigner
	if err := cvVerifyAgreementObjectScalar(object, wrongCoin); err == nil {
		t.Fatal("accepted control signer in the coin role")
	}
}
