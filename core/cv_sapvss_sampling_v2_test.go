package core

import (
	"fmt"
	"math/big"
	"testing"
)

func TestResolveCVV2SamplingMatchesPaperProfiles(t *testing.T) {
	tests := []struct {
		profile                     string
		n, f                        int
		wantProposer, wantValidator int
	}{
		{profile: "original", n: 32, f: 10, wantProposer: 11, wantValidator: 21},
		{profile: "original", n: 48, f: 15, wantProposer: 14, wantValidator: 31},
		{profile: "original", n: 64, f: 21, wantProposer: 16, wantValidator: 43},
		{profile: "original", n: 96, f: 31, wantProposer: 18, wantValidator: 63},
		{profile: "original", n: 128, f: 42, wantProposer: 19, wantValidator: 85},
		{profile: "high-assurance", n: 32, f: 10, wantProposer: 11, wantValidator: 21},
		{profile: "high-assurance", n: 48, f: 15, wantProposer: 16, wantValidator: 31},
		{profile: "high-assurance", n: 64, f: 21, wantProposer: 22, wantValidator: 43},
		{profile: "high-assurance", n: 96, f: 31, wantProposer: 32, wantValidator: 63},
		{profile: "high-assurance", n: 128, f: 42, wantProposer: 37, wantValidator: 85},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-n%d", test.profile, test.n), func(t *testing.T) {
			report, err := ResolveCVV2Sampling(test.n, test.f, test.profile, 3, 3)
			if err != nil {
				t.Fatal(err)
			}
			if report.Profile != test.profile || report.Policy != "exact-finite-population" ||
				report.ProposerSampleSize != test.wantProposer || report.ValidatorSampleSize != test.wantValidator ||
				report.ValidatorThreshold != test.wantValidator/2+1 || report.FaultFraction == "" ||
				report.TotalFailureBudget == "" || report.PerEventFailureTarget == "" {
				t.Fatalf("sampling report=%+v", report)
			}
			total, ok := new(big.Rat).SetString(report.TotalFailureBudget)
			if !ok {
				t.Fatalf("invalid total budget %q", report.TotalFailureBudget)
			}
			actual, ok := new(big.Rat).SetString(report.PerEpochCombinedSamplingFailureBound)
			if !ok || actual.Cmp(total) > 0 {
				t.Fatalf("actual bound %q exceeds total %q", report.PerEpochCombinedSamplingFailureBound, report.TotalFailureBudget)
			}
		})
	}
}

func TestResolveCVV2SamplingUsesTotalBudgetAndMinimalSamples(t *testing.T) {
	report, err := ResolveCVV2Sampling(128, 42, "1e-10", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if report.Profile != "custom" || report.TotalFailureBudget != "1/10000000000" ||
		report.PerEventFailureTarget != "1/20000000000" || report.ProposerSampleSize != 19 ||
		report.ValidatorSampleSize != 85 {
		t.Fatalf("custom sampling report=%+v", report)
	}
	target, _ := new(big.Rat).SetString(report.PerEventFailureTarget)
	previousProposer, err := cvV2ProposerFailureBound(128, 42, report.ProposerSampleSize-1)
	if err != nil || previousProposer.Cmp(target) <= 0 {
		t.Fatalf("proposer sample is not minimal: previous=%v err=%v", previousProposer, err)
	}
	previousValidator := report.ValidatorSampleSize - 1
	_, _, previousValidatorBound, err := cvV2ValidatorFailureBounds(
		128, 42, previousValidator, previousValidator/2+1,
	)
	if err != nil || previousValidatorBound.Cmp(target) <= 0 {
		t.Fatalf("validator sample is not minimal: previous=%v err=%v", previousValidatorBound, err)
	}
}

func TestResolveCVV2SamplingLabelsExplicitSmoke(t *testing.T) {
	report, err := ResolveCVV2Sampling(7, 2, "smoke", 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "smoke" || report.Profile != "smoke" || report.Policy != "explicit-smoke" ||
		report.ProposerSampleSize != 3 || report.ValidatorSampleSize != 2 || report.ValidatorThreshold != 2 ||
		report.TotalFailureBudget != "" || report.PerEventFailureTarget != "" ||
		report.ValidatorCombinedFailureBound != "11/21" {
		t.Fatalf("smoke sampling report=%+v", report)
	}
}

func TestResolveCVV2SamplingRejectsUnsupportedTarget(t *testing.T) {
	for _, target := range []string{"0.01", "1e-0", "2^-0", "paper", "unknown"} {
		if _, err := ResolveCVV2Sampling(128, 42, target, 3, 3); err == nil {
			t.Fatalf("accepted unsupported target %q", target)
		}
	}
}

func TestCVV2SamplingUnionBoundIsExactAndCapped(t *testing.T) {
	report, err := ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if report.ContributorSamplingFailureBound != "0" {
		t.Fatalf("contributor sampling bound=%q, want 0", report.ContributorSamplingFailureBound)
	}
	if got, err := CVV2SamplingUnionBound(report, 3); err != nil || got != "3/7" {
		t.Fatalf("three-epoch union bound=%q err=%v", got, err)
	}
	if got, err := CVV2SamplingUnionBound(report, 8); err != nil || got != "1" {
		t.Fatalf("capped union bound=%q err=%v", got, err)
	}
}
