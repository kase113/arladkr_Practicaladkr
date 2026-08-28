package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"rladkr_go/core"
)

const cvV2ReferenceReportSchema = "arladkr-cvv2-reference-report-v1"

type cvV2ReferenceManifest struct {
	ExperimentID       string                  `json:"experiment_id"`
	ExperimentClass    string                  `json:"experiment_class"`
	SecurityClaim      string                  `json:"security_claim"`
	ExecutionMode      string                  `json:"execution_mode"`
	Protocol           string                  `json:"protocol"`
	SIDPrefix          string                  `json:"sid_prefix"`
	Epoch              int                     `json:"epoch"`
	Runs               int                     `json:"runs"`
	OldNodes           int                     `json:"old_nodes"`
	OldFaults          int                     `json:"old_faults"`
	NewNodes           int                     `json:"new_nodes"`
	NewFaults          int                     `json:"new_faults"`
	Sampling           core.CVV2SamplingReport `json:"sampling"`
	SamplingUnionBound string                  `json:"sampling_union_bound"`
}

type cvV2ReferenceMeanMetrics struct {
	ComponentScalarCiphertextBytes   float64 `json:"component_scalar_ciphertext_bytes"`
	ComponentBlindingCiphertextBytes float64 `json:"component_blinding_ciphertext_bytes"`
	ComponentOwnershipProofBytes     float64 `json:"component_ownership_proof_bytes"`
	FallbackLinkProofBytes           float64 `json:"fallback_link_proof_bytes"`
	FallbackRangeProofBytes          float64 `json:"fallback_range_proof_bytes"`
	ComponentLeafWireBytes           float64 `json:"component_leaf_wire_bytes"`
	AggregatePayloadBytes            float64 `json:"aggregate_payload_bytes"`
	AggregateShareProofBytes         float64 `json:"aggregate_share_proof_bytes"`
	ScalarBoundedDLogMilliseconds    float64 `json:"scalar_bounded_dlog_ms"`
	BlindingGroupDecryptMilliseconds float64 `json:"blinding_group_decryption_ms"`
}

type cvV2ReferenceSummary struct {
	SuccessfulRuns int                       `json:"successful_runs"`
	MeanTimings    core.CVV2ReferenceTimings `json:"mean_timings"`
	MeanMetrics    cvV2ReferenceMeanMetrics  `json:"mean_metrics"`
}

type cvV2ReferenceReport struct {
	Schema   string                                `json:"schema"`
	Manifest cvV2ReferenceManifest                 `json:"manifest"`
	Runs     []*core.CVV2ReferenceExperimentResult `json:"runs,omitempty"`
	Summary  *cvV2ReferenceSummary                 `json:"summary,omitempty"`
}

func buildCVV2ReferenceManifest(
	sidPrefix string, epoch, runs, oldNodes, oldFaults, newNodes, newFaults int,
	sampling core.CVV2SamplingReport, samplingUnionBound string, manifestOnly bool,
) (cvV2ReferenceManifest, error) {
	if strings.TrimSpace(sidPrefix) == "" || epoch <= 0 || runs <= 0 || oldNodes <= 0 || newNodes <= 0 ||
		oldFaults < 0 || oldFaults >= oldNodes || newFaults < 0 || newFaults >= newNodes ||
		oldNodes < 3*oldFaults+1 || newNodes < 3*newFaults+1 ||
		strings.TrimSpace(samplingUnionBound) == "" {
		return cvV2ReferenceManifest{}, fmt.Errorf("invalid CV V2 reference manifest input")
	}
	experimentClass := ""
	securityClaim := ""
	switch {
	case sampling.Target == "smoke" && sampling.Policy == "explicit-smoke":
		experimentClass = "functional-smoke"
		securityClaim = "functional-only-no-negligible-failure-claim"
	case sampling.Target != "smoke" && sampling.Policy == "exact-finite-population" &&
		sampling.TotalFailureBudget != "" && sampling.PerEventFailureTarget != "":
		experimentClass = "finite-population-secure"
		securityClaim = "exact-hypergeometric-total-budget"
	default:
		return cvV2ReferenceManifest{}, fmt.Errorf("inconsistent CV V2 sampling class")
	}
	executionMode := "reference-crypto"
	if manifestOnly {
		executionMode = "manifest-only"
	}
	manifest := cvV2ReferenceManifest{
		ExperimentClass: experimentClass, SecurityClaim: securityClaim, ExecutionMode: executionMode,
		Protocol: core.CVV2ReferenceExperimentProtocol, SIDPrefix: sidPrefix, Epoch: epoch, Runs: runs,
		OldNodes: oldNodes, OldFaults: oldFaults, NewNodes: newNodes, NewFaults: newFaults,
		Sampling: sampling, SamplingUnionBound: samplingUnionBound,
	}
	identity := struct {
		Schema    string                  `json:"schema"`
		Protocol  string                  `json:"protocol"`
		SIDPrefix string                  `json:"sid_prefix"`
		Epoch     int                     `json:"epoch"`
		Runs      int                     `json:"runs"`
		OldNodes  int                     `json:"old_nodes"`
		OldFaults int                     `json:"old_faults"`
		NewNodes  int                     `json:"new_nodes"`
		NewFaults int                     `json:"new_faults"`
		Sampling  core.CVV2SamplingReport `json:"sampling"`
	}{
		Schema: cvV2ReferenceReportSchema, Protocol: manifest.Protocol, SIDPrefix: sidPrefix,
		Epoch: epoch, Runs: runs, OldNodes: oldNodes, OldFaults: oldFaults,
		NewNodes: newNodes, NewFaults: newFaults, Sampling: sampling,
	}
	wire, err := json.Marshal(identity)
	if err != nil {
		return cvV2ReferenceManifest{}, err
	}
	digest := sha256.Sum256(wire)
	manifest.ExperimentID = hex.EncodeToString(digest[:16])
	return manifest, nil
}

func buildCVV2ReferenceReport(
	manifest cvV2ReferenceManifest,
	runs []*core.CVV2ReferenceExperimentResult,
) (cvV2ReferenceReport, error) {
	if manifest.ExecutionMode != "reference-crypto" || len(runs) != manifest.Runs || len(runs) == 0 {
		return cvV2ReferenceReport{}, fmt.Errorf("invalid CV V2 reference report run set")
	}
	for index, result := range runs {
		if result == nil || result.Protocol != manifest.Protocol || result.SID != fmt.Sprintf("%s-run-%d", manifest.SIDPrefix, index+1) ||
			int(result.Epoch) != manifest.Epoch || result.OldNodes != manifest.OldNodes || result.OldFaults != manifest.OldFaults ||
			result.NewNodes != manifest.NewNodes || result.NewFaults != manifest.NewFaults ||
			!reflect.DeepEqual(result.Sampling, manifest.Sampling) || result.SamplingEpochs != manifest.Runs ||
			result.SamplingUnionBound != manifest.SamplingUnionBound || result.AggregateDigest == "" ||
			result.HandoffDigest == "" || result.PublicKey == "" {
			return cvV2ReferenceReport{}, fmt.Errorf("CV V2 reference run %d does not match manifest", index+1)
		}
	}
	summary := summarizeCVV2ReferenceRuns(runs)
	return cvV2ReferenceReport{
		Schema: cvV2ReferenceReportSchema, Manifest: manifest, Runs: runs, Summary: &summary,
	}, nil
}

func summarizeCVV2ReferenceRuns(runs []*core.CVV2ReferenceExperimentResult) cvV2ReferenceSummary {
	count := float64(len(runs))
	var summary cvV2ReferenceSummary
	summary.SuccessfulRuns = len(runs)
	for _, result := range runs {
		t := result.Timings
		summary.MeanTimings.KeySetup += t.KeySetup / count
		summary.MeanTimings.LeafGeneration += t.LeafGeneration / count
		summary.MeanTimings.Components += t.Components / count
		summary.MeanTimings.Pool += t.Pool / count
		summary.MeanTimings.Aggregate += t.Aggregate / count
		summary.MeanTimings.Validation += t.Validation / count
		summary.MeanTimings.Agreement += t.Agreement / count
		summary.MeanTimings.Handoff += t.Handoff / count
		summary.MeanTimings.Recovery += t.Recovery / count
		summary.MeanTimings.Shares += t.Shares / count
		summary.MeanTimings.ReferenceEpoch += t.ReferenceEpoch / count
		summary.MeanTimings.Total += t.Total / count
		m := result.Metrics
		summary.MeanMetrics.ComponentScalarCiphertextBytes += float64(m.ComponentScalarCiphertextBytes) / count
		summary.MeanMetrics.ComponentBlindingCiphertextBytes += float64(m.ComponentBlindingCiphertextBytes) / count
		summary.MeanMetrics.ComponentOwnershipProofBytes += float64(m.ComponentOwnershipProofBytes) / count
		summary.MeanMetrics.FallbackLinkProofBytes += float64(m.FallbackLinkProofBytes) / count
		summary.MeanMetrics.FallbackRangeProofBytes += float64(m.FallbackRangeProofBytes) / count
		summary.MeanMetrics.ComponentLeafWireBytes += float64(m.ComponentLeafWireBytes) / count
		summary.MeanMetrics.AggregatePayloadBytes += float64(m.AggregatePayloadBytes) / count
		summary.MeanMetrics.AggregateShareProofBytes += float64(m.AggregateShareProofBytes) / count
		summary.MeanMetrics.ScalarBoundedDLogMilliseconds += m.ScalarBoundedDLogMilliseconds / count
		summary.MeanMetrics.BlindingGroupDecryptMilliseconds += m.BlindingGroupDecryptMilliseconds / count
	}
	return summary
}
