package main

import (
	"fmt"
	"testing"

	"rladkr_go/core"
)

func TestBuildCVV2ReferenceManifestSeparatesSmokeAndSecureClaims(t *testing.T) {
	smoke, err := core.ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	smokeManifest, err := buildCVV2ReferenceManifest("paper-smoke", 1, 2, 7, 2, 4, 1, smoke, "2/7", false)
	if err != nil {
		t.Fatal(err)
	}
	if smokeManifest.ExperimentClass != "functional-smoke" ||
		smokeManifest.SecurityClaim != "functional-only-no-negligible-failure-claim" ||
		smokeManifest.ExperimentID == "" {
		t.Fatalf("misclassified smoke manifest: %+v", smokeManifest)
	}
	repeated, err := buildCVV2ReferenceManifest("paper-smoke", 1, 2, 7, 2, 4, 1, smoke, "2/7", true)
	if err != nil || repeated.ExperimentID != smokeManifest.ExperimentID || repeated.ExecutionMode != "manifest-only" {
		t.Fatalf("manifest identity is not stable across execution modes: %+v err=%v", repeated, err)
	}

	secure, err := core.ResolveCVV2Sampling(128, 42, "original", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	secureManifest, err := buildCVV2ReferenceManifest("paper-secure", 1, 1, 128, 42, 4, 1, secure,
		secure.PerEpochCombinedSamplingFailureBound, true)
	if err != nil {
		t.Fatal(err)
	}
	if secureManifest.ExperimentClass != "finite-population-secure" ||
		secureManifest.SecurityClaim != "exact-hypergeometric-total-budget" ||
		secureManifest.Sampling.ProposerSampleSize != 19 || secureManifest.Sampling.ValidatorSampleSize != 85 {
		t.Fatalf("misclassified secure manifest: %+v", secureManifest)
	}
	if _, err := buildCVV2ReferenceManifest("invalid", 1, 1, 7, 2, 4, 2, smoke, "1", true); err == nil {
		t.Fatal("manifest-only accepted a new committee violating n >= 3f+1")
	}
}

func TestBuildCVV2ReferenceReportValidatesRunsAndComputesMeans(t *testing.T) {
	sampling, err := core.ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildCVV2ReferenceManifest("paper-smoke", 1, 2, 7, 2, 4, 1, sampling, "2/7", false)
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]*core.CVV2ReferenceExperimentResult, 2)
	for i := range runs {
		runs[i] = &core.CVV2ReferenceExperimentResult{
			Protocol: core.CVV2ReferenceExperimentProtocol, SID: fmt.Sprintf("paper-smoke-run-%d", i+1), Epoch: 1,
			OldNodes: 7, OldFaults: 2, NewNodes: 4, NewFaults: 1,
			Sampling: sampling, SamplingEpochs: 2, SamplingUnionBound: "2/7",
			AggregateDigest: "aggregate", HandoffDigest: "handoff", PublicKey: "public",
			Timings: core.CVV2ReferenceTimings{Total: float64(10 + 10*i), Shares: float64(2 + 2*i)},
			Metrics: core.CVV2ReferenceMetrics{AggregatePayloadBytes: 100 + 100*i,
				ScalarBoundedDLogMilliseconds: float64(4 + 4*i)},
		}
	}
	report, err := buildCVV2ReferenceReport(manifest, runs)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != cvV2ReferenceReportSchema || report.Summary == nil || report.Summary.SuccessfulRuns != 2 ||
		report.Summary.MeanTimings.Total != 15 || report.Summary.MeanTimings.Shares != 3 ||
		report.Summary.MeanMetrics.AggregatePayloadBytes != 150 ||
		report.Summary.MeanMetrics.ScalarBoundedDLogMilliseconds != 6 {
		t.Fatalf("incorrect CV V2 reference summary: %+v", report.Summary)
	}
	runs[1].SamplingUnionBound = "wrong"
	if _, err := buildCVV2ReferenceReport(manifest, runs); err == nil {
		t.Fatal("accepted a run that does not match its manifest")
	}
}
