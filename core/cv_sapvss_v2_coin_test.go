package core

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCVV2SampleWithoutReplacementIsCanonicalAndDomainSeparated(t *testing.T) {
	roster := []int{9, 2, 7, 4, 1, 6, 3, 8, 5}
	coin := []byte("fixed public threshold coin output")
	first, err := cvSampleWithoutReplacementV2(roster, coin, cvV2ProposerSampleTag, 5)
	if err != nil {
		t.Fatalf("sample V2 proposers: %v", err)
	}
	second, err := cvSampleWithoutReplacementV2([]int{1, 2, 3, 4, 5, 6, 7, 8, 9}, coin, cvV2ProposerSampleTag, 5)
	if err != nil {
		t.Fatalf("resample V2 proposers: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("sampling depends on input roster order: %v / %v", first, second)
	}
	seen := make(map[int]struct{}, len(first))
	for _, member := range first {
		if member < 1 || member > 9 {
			t.Fatalf("sampled member outside roster: %d", member)
		}
		if _, duplicate := seen[member]; duplicate {
			t.Fatalf("sample contains duplicate member: %v", first)
		}
		seen[member] = struct{}{}
	}
	validators, err := cvSampleWithoutReplacementV2(roster, coin, cvV2ValidatorSampleTag, 5)
	if err != nil {
		t.Fatalf("sample V2 validators: %v", err)
	}
	if reflect.DeepEqual(first, validators) {
		t.Fatalf("proposer and validator samples reused the same domain: %v", first)
	}
}

func TestCVV2SampleWithoutReplacementRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		roster []int
		coin   []byte
		tag    string
		count  int
	}{
		{nil, []byte{1}, cvV2ProposerSampleTag, 1},
		{[]int{1, 1}, []byte{1}, cvV2ProposerSampleTag, 1},
		{[]int{1}, nil, cvV2ProposerSampleTag, 1},
		{[]int{1}, []byte{1}, "", 1},
		{[]int{1}, []byte{1}, cvV2ProposerSampleTag, 0},
		{[]int{1}, []byte{1}, cvV2ProposerSampleTag, 2},
	} {
		if _, err := cvSampleWithoutReplacementV2(test.roster, test.coin, test.tag, test.count); err == nil {
			t.Fatalf("accepted invalid V2 sampler input: %+v", test)
		}
	}
}

func TestCVCoinOutputV2BindsInvocationCertificateAndSamples(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := cvEligibilityCoinInvocationV2(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cvCoinInvocationDigestV2(invocation)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[int][]byte, coinSigner.Threshold())
	for _, member := range cfg.OldCommittee[:coinSigner.Threshold()] {
		share, signErr := coinSigner.SignShare(member, cvV2CoinDomain, digest)
		if signErr != nil {
			t.Fatal(signErr)
		}
		shares[member] = share
	}
	certificate, err := coinSigner.Recover(cvV2CoinDomain, digest, shares)
	if err != nil {
		t.Fatal(err)
	}
	output, err := cvBuildCoinOutputV2(invocation, certificate, coinSigner)
	if err != nil || cvVerifyCoinOutputV2(output, invocation, coinSigner) != nil {
		t.Fatalf("verify V2 coin output: %v", err)
	}
	if _, err := cvCoinOutputV2CanonicalBytes(output); err != nil {
		t.Fatalf("canonical V2 coin output: %v", err)
	}
	proposers, validators, err := cvDeriveEligibilitySamplesV2(cfg.OldCommittee, output.Value, params.proposerSampleSize, params.validatorSampleSize)
	if err != nil || len(proposers) != params.proposerSampleSize || len(validators) != params.validatorSampleSize {
		t.Fatalf("derive V2 eligibility samples: %v", err)
	}
	contributor, err := cvContributorCoinInvocationV2(hashBytes([]byte("context")), 0, hashBytes([]byte("pool")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(invocation, contributor) {
		t.Fatal("eligibility and contributor coin invocations collide")
	}
	if err := cvVerifyCoinOutputV2(output, contributor, coinSigner); err == nil {
		t.Fatal("accepted eligibility output for contributor invocation")
	}
}
