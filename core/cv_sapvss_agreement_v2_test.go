package core

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestCVAgreementObjectV2CompactRoundTripAndTamper(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := cvAgreementObjectV2CompactCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	full, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) >= len(full) {
		t.Fatalf("compact wire did not shrink: compact=%d full=%d", len(compact), len(full))
	}
	t.Logf("compact-v1 agreement bytes: compact=%d full=%d", len(compact), len(full))
	decoded, err := cvDecodeAgreementObjectV2(compact, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyAgreementObjectV2(decoded, public); err != nil {
		t.Fatalf("compact predicate rejected logical object: %v", err)
	}
	mutated := append([]byte(nil), compact...)
	mutated[len(mutated)-1] ^= 1
	if decodedMutated, err := cvDecodeAgreementObjectV2(mutated, public.Params, validators); err == nil {
		if cvVerifyAgreementObjectV2(decodedMutated, public) == nil {
			t.Fatal("compact predicate accepted tampered wire")
		}
	}
}

func TestCVAgreementObjectV2CompactDeltaBoundaries(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	object.SelectedIndices = []int{0, 1, public.Params.poolSize - 1}
	wire, err := cvAgreementObjectV2CompactCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAgreementObjectV2(wire, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(decoded.SelectedIndices, object.SelectedIndices) {
		t.Fatalf("selection roundtrip: got %v want %v", decoded.SelectedIndices, object.SelectedIndices)
	}
}

func TestCVRunAgreementV2RejectsInvalidCandidateBeforeNetwork(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	invalid := *object
	invalid.Header.AggregateDigest = append([]byte(nil), object.Header.AggregateDigest...)
	invalid.Header.AggregateDigest[0] ^= 1
	cfg := cvV2ParamsTestConfig()
	cfg.LocalNodeIDs = []int{cfg.OldCommittee[0]}
	if _, _, _, err := cvRunAgreementV2(context.Background(), cfg, &invalid, public); err == nil {
		t.Fatal("CV V2 agreement entered network with an invalid local candidate")
	}
}

func cvRecoverThresholdCertificateV2ForTest(t *testing.T, signer *tblsThresholdSigner, members []int, domain string, digest []byte) []byte {
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

func cvAgreementObjectV2Fixture(t *testing.T) (*cvAgreementObjectV2, cvAgreementPublicContextV2) {
	t.Helper()
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keyPublic := filepath.Join(t.TempDir(), "threshold-public")
	keySecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(keyPublic, keySecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(keyPublic, keySecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}
	validatorPublic := filepath.Join(t.TempDir(), "validator-public")
	validatorSecret := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	validatorKeys, err := cvLoadValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	eligibilityInvocation, err := cvEligibilityCoinInvocationV2(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	eligibilityDigest, err := cvCoinInvocationDigestV2(eligibilityInvocation)
	if err != nil {
		t.Fatal(err)
	}
	eligibilityCertificate := cvRecoverThresholdCertificateV2ForTest(t, coinSigner, cfg.OldCommittee, cvV2CoinDomain, eligibilityDigest)
	eligibilityCoin, err := cvBuildCoinOutputV2(eligibilityInvocation, eligibilityCertificate, coinSigner)
	if err != nil {
		t.Fatal(err)
	}
	proposers, validatorSample, err := cvDeriveEligibilitySamplesV2(cfg.OldCommittee, eligibilityCoin.Value, params.proposerSampleSize, params.validatorSampleSize)
	if err != nil {
		t.Fatal(err)
	}
	proposer := proposers[0]

	contextDigest := hashBytes([]byte("agreement V2 context"))
	components := cvPoolV2TestComponents(t, contextDigest, params)
	for i := range components {
		statement, err := cvAPDBStoredStatementV2(components[i].Lock.InstanceDigest, components[i].Lock.Root)
		if err != nil {
			t.Fatal(err)
		}
		components[i].Lock.Certificate = cvRecoverThresholdCertificateV2ForTest(t, apdbSigner, cfg.OldCommittee, cvAPDBStoredDomain, statement)
	}
	pool, err := cvBuildPoolV2(contextDigest, proposer, components, params)
	if err != nil {
		t.Fatal(err)
	}
	poolStatement, err := cvPoolCertificateStatementV2(contextDigest, proposer, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	poolCert := cvPoolCertificateV2{PoolDigest: append([]byte(nil), pool.Digest...),
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, controlSigner, cfg.OldCommittee, cvPoolCertV2Domain, poolStatement)}

	invocation, err := cvContributorCoinInvocationV2(contextDigest, proposer, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	coinDigest, err := cvCoinInvocationDigestV2(invocation)
	if err != nil {
		t.Fatal(err)
	}
	coinCertificate := cvRecoverThresholdCertificateV2ForTest(t, coinSigner, cfg.OldCommittee, cvV2CoinDomain, coinDigest)
	coin, err := cvBuildCoinOutputV2(invocation, coinCertificate, coinSigner)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := cvSelectedPoolIndicesV2(params.poolSize, params.componentCount, coin.Value)
	if err != nil {
		t.Fatal(err)
	}
	selectionDigest, err := cvSelectionDigestV2(coin, selected, params.poolSize, params.componentCount)
	if err != nil {
		t.Fatal(err)
	}
	aggregateRoot := hashBytes([]byte("agreement V2 aggregate root"))
	aggregateInstance, err := cvAggregateInstanceDigestV2(contextDigest, proposer, pool.Digest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	header := cvAggregateHeaderV2{ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
		SelectionDigest: selectionDigest, AggregateDigest: hashBytes([]byte("agreement V2 aggregate")),
		PayloadDigest: hashBytes([]byte("agreement V2 payload")), APDBInstance: aggregateInstance, APDBRoot: aggregateRoot}
	arcStatement, err := cvAPDBStoredStatementV2(aggregateInstance, aggregateRoot)
	if err != nil {
		t.Fatal(err)
	}
	arc := cvAPDBLockV2{InstanceDigest: append([]byte(nil), aggregateInstance...), Root: append([]byte(nil), aggregateRoot...),
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, apdbSigner, cfg.OldCommittee, cvAPDBStoredDomain, arcStatement)}
	votes := make(map[int][]byte, params.validatorThreshold)
	for _, member := range validatorSample[:params.validatorThreshold] {
		votes[member], err = cvSignValidationV2(member, &header, validatorSample, validatorKeys)
		if err != nil {
			t.Fatal(err)
		}
	}
	vCert, err := cvBuildValidationCertificateV2(&header, validatorSample, params.validatorThreshold, votes, validatorKeys)
	if err != nil {
		t.Fatal(err)
	}
	object := &cvAgreementObjectV2{Header: header, Pool: *pool, PoolCert: poolCert, ContributorCoin: *coin,
		SelectedIndices: selected, VCert: *vCert, ARC: arc}
	public := cvAgreementPublicContextV2{SID: cfg.SID, Epoch: uint64(cfg.Epoch), ContextDigest: contextDigest,
		OldCommittee: append([]int(nil), cfg.OldCommittee...), EligibilityCoin: eligibilityCoin, Params: params,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner, ValidatorKeys: validatorKeys}
	return object, public
}

func TestCVAgreementObjectV2PublicPredicateAndCodec(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	if err := cvVerifyAgreementObjectV2(object, public); err != nil {
		t.Fatalf("verify V2 agreement object: %v", err)
	}
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAgreementObjectV2(wire, public.Params, validators)
	if err != nil || !bytes.Equal(decoded.Header.APDBInstance, object.Header.APDBInstance) {
		t.Fatalf("V2 agreement object codec: %v", err)
	}
	predicate := cvAggregatePredicateV2(public)
	if !predicate(0, wire) {
		t.Fatal("public predicate rejected valid V2 agreement object")
	}
	if predicate(0, append(append([]byte(nil), wire...), 0)) {
		t.Fatal("public predicate accepted trailing agreement bytes")
	}
}

func TestCVAgreementObjectV2PredicateRejectsPublicBindingMutations(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	badSelection := *object
	badSelection.SelectedIndices = append([]int(nil), object.SelectedIndices...)
	badSelection.SelectedIndices[0], badSelection.SelectedIndices[1] = badSelection.SelectedIndices[1], badSelection.SelectedIndices[0]
	if err := cvVerifyAgreementObjectV2(&badSelection, public); err == nil {
		t.Fatal("accepted reordered contributor selection")
	}
	badARC := *object
	badARC.ARC = object.ARC
	badARC.ARC.Root = append([]byte(nil), object.ARC.Root...)
	badARC.ARC.Root[0] ^= 1
	if err := cvVerifyAgreementObjectV2(&badARC, public); err == nil {
		t.Fatal("accepted ARC/header root mismatch")
	}
	wrongEligibility := public
	wrongEligibility.SID += "-wrong"
	if err := cvVerifyAgreementObjectV2(object, wrongEligibility); err == nil {
		t.Fatal("accepted ineligible V2 proposer")
	}
	badVCert := *object
	badVCert.VCert = object.VCert
	badVCert.VCert.AggregateSignature = append([]byte(nil), object.VCert.AggregateSignature...)
	badVCert.VCert.AggregateSignature[len(badVCert.VCert.AggregateSignature)-1] ^= 1
	if err := cvVerifyAgreementObjectV2(&badVCert, public); err == nil {
		t.Fatal("accepted invalid VCert")
	}
}

func TestCVAgreementObjectV2RejectsThresholdSignerRoleSwaps(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)

	swappedLocks := public
	swappedLocks.APDBSigner, swappedLocks.ControlSigner = public.ControlSigner, public.APDBSigner
	if err := cvVerifyAgreementObjectV2(object, swappedLocks); err == nil {
		t.Fatal("accepted swapped APDB and control signers")
	}

	wrongCoin := public
	wrongCoin.CoinSigner = public.ControlSigner
	if err := cvVerifyAgreementObjectV2(object, wrongCoin); err == nil {
		t.Fatal("accepted control signer in the coin role")
	}
}
