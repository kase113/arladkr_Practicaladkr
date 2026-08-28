package main

import (
	"rladkr_go/core"
	"strings"
	"testing"
	"time"
)

func TestResultProtocolLatencyUsesSlowestLocalDecision(t *testing.T) {
	result := &core.EpochResult{PerNode: []core.NodeOutput{
		{NodeID: 1, Latency: 1250 * time.Millisecond},
		{NodeID: 2, Latency: 1500 * time.Millisecond},
	}}
	if got := resultProtocolLatencyMs(result); got != 1500 {
		t.Fatalf("protocol latency = %.2fms, want 1500ms", got)
	}
	if got := resultProtocolLatencyMs(nil); got != 0 {
		t.Fatalf("nil protocol latency = %.2fms, want 0", got)
	}
}

func TestValidateCVV2BenchmarkShapeRejectsRotationAndResumeClaims(t *testing.T) {
	if err := validateCVV2BenchmarkShape(1, 1); err != nil {
		t.Fatalf("fresh single epoch rejected: %v", err)
	}
	for _, tc := range []struct {
		runs   int
		epochs int
	}{{2, 1}, {1, 2}, {0, 1}, {1, 0}} {
		err := validateCVV2BenchmarkShape(tc.runs, tc.epochs)
		if err == nil || !strings.Contains(err.Error(), "key rotation and incomplete-epoch resume are unsupported") {
			t.Fatalf("shape (%d,%d) did not fail with the experiment boundary: %v", tc.runs, tc.epochs, err)
		}
	}
}

func TestAdmitAggPassRatio(t *testing.T) {
	if got := admitAggPassRatio(0, 0); got != 0 {
		t.Fatalf("expected 0 ratio on zero attempts, got %.4f", got)
	}
	if got := admitAggPassRatio(3, 4); got != 0.75 {
		t.Fatalf("expected 0.75 ratio, got %.4f", got)
	}
}

func TestFormatBenchResultIncludesEffectiveKappa(t *testing.T) {
	effective := core.NormalizeConfig(core.Config{FOld: 1, FNew: 1, Kappa: 0}).Kappa
	line := formatBenchResult(benchResultInput{kappa: effective, runs: 1})
	if !strings.Contains(line, " kappa=2 ") {
		t.Fatalf("benchmark output missing effective kappa: %s", line)
	}
}

func TestFormatBenchResultIncludesAPVSSModeAndBackendStatus(t *testing.T) {
	t.Setenv("RLADKR_CV_PRIMARY_GRACE_MS", "")
	t.Setenv("RLADKR_CV_PROPOSER_SLOT_GRACE_MS", "")
	t.Setenv("RLADKR_VALIDATION_FIRST_WAVE_GRACE_MS", "")
	line := formatBenchResult(benchResultInput{
		runs:                  1,
		apvssMode:             core.APVSSModeFullPublicVE,
		apvssBackendStatus:    "functional-prototype-backend-gate-pending",
		apvssFullProofProfile: core.APVSSFullProofExact,
		apvssFallbackProfile:  "none",
		securityProfile:       "static-cv-sapvss-full-proof-prototype-unreviewed",
	})
	for _, field := range []string{
		"cv_candidate_mode=" + core.CVAggregateCandidateMode,
		"cv_primary_grace_ms=10000",
		"cv_proposer_slot_grace_ms=10000",
		"cv_validation_first_wave_extra=2",
		"cv_validation_first_wave_grace_ms=2000",
		"cv_primary_pool_grace_ms=250",
		"apvss_mode=full-public-ve",
		"apvss_backend_status=functional-prototype-backend-gate-pending",
		"apvss_full_proof_profile=exact",
		"apvss_fallback_profile=none",
		"security_profile=static-cv-sapvss-full-proof-prototype-unreviewed",
	} {
		if !strings.Contains(line, field) {
			t.Fatalf("benchmark result missing %q: %s", field, line)
		}
	}
}

func TestSummarizeConsensusHashBindsEpochSequence(t *testing.T) {
	first := summarizeConsensusHash([]runStat{{consensusHash: "a"}, {consensusHash: "b"}})
	second := summarizeConsensusHash([]runStat{{consensusHash: "b"}, {consensusHash: "a"}})
	if first == "none" || first == "mixed" || first == second {
		t.Fatalf("sequence digest is not ordered: first=%q second=%q", first, second)
	}
}

func TestFormatBenchResultReportsCommitteeFaultThresholds(t *testing.T) {
	asymmetric := formatBenchResult(benchResultInput{fOld: 1, fNew: 2, runs: 1})
	for _, token := range []string{" f_old=1 ", " f_new=2 "} {
		if !strings.Contains(asymmetric, token) {
			t.Fatalf("asymmetric benchmark output missing %q: %s", token, asymmetric)
		}
	}

	balanced := formatBenchResult(benchResultInput{fOld: 1, fNew: 1, runs: 1})
	for _, token := range []string{" f_old=1 ", " f_new=1 "} {
		if !strings.Contains(balanced, token) {
			t.Fatalf("balanced benchmark output missing %q: %s", token, balanced)
		}
	}
}

func TestFormatBenchResultIncludesARLADKRMetrics(t *testing.T) {
	stats := []runStat{
		{
			latencyMs:             100,
			setupMs:               10,
			recoverBarrierWaitMs:  20,
			recoverServiceGraceMs: 30,
			completedNodes:        4,
			decidedSetMean:        3,
			aggRLOReadyMs:         5,
			admitAggAttempts:      2,
			admitAggPasses:        2,
			recoverAggSuccess:     1,
		},
		{
			latencyMs:             200,
			setupMs:               20,
			recoverBarrierWaitMs:  40,
			recoverServiceGraceMs: 60,
			completedNodes:        4,
			decidedSetMean:        3,
			aggRLOReadyMs:         7,
			admitAggAttempts:      2,
			admitAggPasses:        1,
			recoverAggSuccess:     1,
		},
	}
	line := formatBenchResult(benchResultInput{
		n:                          4,
		fOld:                       1,
		fNew:                       1,
		kappa:                      2,
		runs:                       2,
		timeoutMs:                  90000,
		apvssProvider:              "cv-sapvss",
		apvssOutput:                "scalar",
		securityProfile:            "static-cv-sapvss-phase1-materialized",
		deriveMode:                 "scalar",
		successRuns:                2,
		attemptedEpochs:            3,
		totalAttemptLatencyMs:      600,
		totalAttemptServiceGraceMs: 90,
		stats:                      stats,
	})
	for _, token := range []string{
		"mean_aggrlo_ready_ms=",
		"admitagg_pass_ratio=",
		"recoveragg_success_ratio=",
		"mean_recover_service_grace_ms=45.00",
		"mean_online_protocol_ms=60.00",
		"mean_online_phase_wall_ms=60.00",
		"mean_all_latency_ms=170.00",
		"mean_raw_latency_ms=150.00",
		"mean_raw_all_latency_ms=200.00",
		"p50_raw_latency_ms=100.00",
		"p95_raw_latency_ms=100.00",
		"latency_reporting=service_grace_adjusted",
		"protocol=ARLADKR-GO",
		"apvss_provider=cv-sapvss",
		"apvss_output=scalar",
		"security_profile=static-cv-sapvss-phase1-materialized",
		"derive_mode=scalar",
	} {
		if !strings.Contains(line, token) {
			t.Fatalf("benchmark output missing token %q: %s", token, line)
		}
	}
}

func TestFormatBenchResultIncludesCVPhaseLabels(t *testing.T) {
	t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", "1")
	sampling, err := core.ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	line := formatBenchResult(benchResultInput{
		runs:                 1,
		cvSampling:           sampling,
		cvSamplingEpochs:     3,
		cvSamplingUnionBound: "3/7",
		stats: []runStat{{
			cvComponentCount: 2, cvARCHolderCount: 3, cvRecoveredShardCount: 2,
			cvVerifiedReceiptCount: 2, cvLeafBuildMs: 7, cvComponentDisperseMs: 1, cvComponentCollectionMs: 2,
			cvEligibilityCoinMs: 2.5, cvProposerSlotsMs: 3.5, cvCoinFanoutMs: 4.5,
			cvCandidateFanoutACKWaitMs: 5.5, cvCandidateFanoutRetryWaitMs: 6.5,
			cvCandidateFanoutMaxPeerMs: 7.5, cvCandidateFanoutAttempts: 8, cvCandidateFanoutRetries: 9,
			cvAggregateDisperseMs: 3, cvAggregateAgreementMs: 4, cvRecoverShardMs: 5,
			cvReceiptMs: 6, cvAPVSSACKCount: 5, cvAPVSSFallbackCount: 2,
			cvAPVSSProofBytes: 101, cvAPVSSLeafWireBytes: 202,
			cvCompletedCandidates: 2, cvPoolWireBytes: 301, cvValidationRequestBytes: 302,
			cvAgreementObjectBytes: 303, cvAggregatePayloadBytes: 304, cvAggregateAPDBBytes: 305,
			cvPoolCertificateBytes: 306, cvValidationCertificateBytes: 307, cvARCCertificateBytes: 308,
			cvDecisionCertificateBytes: 309, cvHandoffWireBytes: 310,
			cvProposerRecoverySentBytes: 401, cvProposerRecoveryRecvBytes: 402,
			cvProposerRecoveryMs: 4.5, cvProposerCatalogVerificationMs: 4.75,
			cvProposerCatalogScanCount: 3, cvProposerRejectedCount: 1,
			cvDealerPayloadSentBytes: 411, cvDealerHintSentBytes: 412,
			cvHolderFragmentSentBytes: 413, cvComponentRecoveryLateRecvBytes: 414,
			cvComponentDirectPayloadHits: 4, cvComponentFragmentRecoveries: 5,
			cvValidatorComponentRecoverySentBytes: 501, cvValidatorComponentRecoveryRecvBytes: 502,
			cvValidatorComponentRecoveryMs: 5.5, cvValidatorAggregateRecoverySentBytes: 601,
			cvValidatorAggregateRecoveryRecvBytes: 602, cvValidatorAggregateRecoveryMs: 6.5,
			cvARCFormationMs: 0.401, cvValidationCertificateFormationMs: 0.502,
			cvDecisionCertificateFormationMs: 0.603,
			cvScalarBoundedDLogMs:            0.704,
			cvBlindingGroupDecryptionMs:      0.805,
			cvNewAggregateRecoveryMs:         7.5,
			cvAggregateGateWaitMs:            7, cvAggregateLeafLoadMs: 8, cvAggregateBuildMs: 9,
			cvAggregateRSMs: 10, cvAggregateHeaderTokenMs: 11, cvAggregateOfferSendMs: 12,
			cvAggregateARCWaitMs: 13, cvAggregateCertificateMs: 14,
			phaseSentBytes: map[string]float64{"component_disperse": 10, "candidate_formation": 11,
				"aggregate_agreement": 12, "recover_shard": 14, "receipt": 15,
				"mvba_pd_data": 16, "mvba_rc_data": 17, "mvba_certificate": 18,
				"component_apdb_dispersal": 31, "pool_coin": 32, "validation_request": 33,
				"aggregate_apdb_dispersal": 34, "candidate_relay": 35, "decision_handoff": 36,
				"new_aggregate_recovery": 37, "new_share_exchange": 38},
			phaseRecvBytes: map[string]float64{
				"mvba_pd_data": 19, "mvba_rc_data": 20, "mvba_certificate": 21,
				"component_apdb_dispersal": 41, "pool_coin": 42, "validation_request": 43,
				"aggregate_apdb_dispersal": 44, "candidate_relay": 45, "decision_handoff": 46,
				"new_aggregate_recovery": 47, "new_share_exchange": 48,
			},
		}},
	})
	for _, token := range []string{
		"mean_cv_component_count=2", "mean_cv_arc_holder_count=3",
		"mean_proposer_catalog_verify_ms=4.75",
		"mean_cv_recovered_shard_count=2", "mean_cv_verified_receipt_count=2",
		"leaf_build_ms=7", "component_disperse_ms=1", "candidate_formation_ms=2",
		"eligibility_coin_ms=2.50", "proposer_slots_ms=3.50", "mean_coin_fanout_ms=4.50", "aggregate_disperse_ms=3",
		"mean_candidate_ack_wait_ms=5.50", "mean_candidate_retry_wait_ms=6.50",
		"mean_candidate_fanout_max_peer_ms=7.50", "mean_candidate_fanout_attempts=8", "mean_candidate_fanout_retries=9",
		"aggregate_agreement_ms=4", "recover_shard_ms=5", "receipt_ms=6",
		"mean_apvss_ack_count=5.00", "mean_apvss_fallback_count=2.00",
		"mean_apvss_proof_bytes=101", "mean_apvss_leaf_wire_bytes=202",
		"mean_completed_candidate_count=2", "mean_pool_wire_bytes=301",
		"mean_validation_request_wire_bytes=302", "mean_agreement_object_wire_bytes=303",
		"mean_aggregate_payload_bytes=304", "mean_aggregate_apdb_encoded_bytes=305",
		"mean_pool_certificate_bytes=306", "mean_validation_certificate_bytes=307",
		"mean_arc_certificate_bytes=308", "mean_decision_certificate_bytes=309", "mean_handoff_wire_bytes=310",
		"mean_proposer_component_recovery_sent_bytes=401", "mean_proposer_component_recovery_recv_bytes=402",
		"mean_proposer_component_recovery_ms=4.50", "mean_proposer_catalog_scan_count=3",
		"mean_proposer_rejected_component_count=1",
		"cv_payload_hints=true", "cv_component_recovery_schedule=dealer-first", "cv_component_direct_grace_ms=250",
		"cv_component_dealer_response=normal",
		"mean_dealer_payload_sent_bytes=411", "mean_dealer_hint_sent_bytes=412",
		"mean_holder_fragment_sent_bytes=413", "mean_component_recovery_late_recv_bytes=414",
		"mean_component_direct_payload_hits=4", "mean_component_fragment_recoveries=5",
		"mean_validator_component_recovery_sent_bytes=501", "mean_validator_component_recovery_recv_bytes=502",
		"mean_validator_component_recovery_ms=5.50",
		"mean_validator_aggregate_recovery_sent_bytes=601", "mean_validator_aggregate_recovery_recv_bytes=602",
		"mean_validator_aggregate_recovery_ms=6.50",
		"mean_arc_formation_ms=0.401", "mean_vcert_formation_ms=0.502", "mean_deccert_formation_ms=0.603",
		"mean_scalar_bounded_dlog_ms=0.704", "mean_blinding_group_decryption_ms=0.805",
		"aggregate_gate_wait_ms=7.00", "aggregate_leaf_load_ms=8.00",
		"aggregate_build_ms=9.00", "aggregate_rs_ms=10.00",
		"aggregate_header_token_ms=11.00", "aggregate_offer_send_ms=12.00",
		"aggregate_arc_wait_ms=13.00", "aggregate_certificate_ms=14.00",
		"mean_component_disperse_sent_bytes=10", "mean_candidate_formation_sent_bytes=11",
		"mean_aggregate_agreement_sent_bytes=12",
		"mean_recover_shard_sent_bytes=14", "mean_receipt_sent_bytes=15",
		"mean_mvba_pd_data_sent_bytes=16", "mean_mvba_pd_data_recv_bytes=19",
		"mean_mvba_rc_data_sent_bytes=17", "mean_mvba_rc_data_recv_bytes=20",
		"mean_mvba_certificate_sent_bytes=18", "mean_mvba_certificate_recv_bytes=21",
		"mean_component_apdb_dispersal_sent_bytes=31", "mean_component_apdb_dispersal_recv_bytes=41",
		"mean_pool_coin_sent_bytes=32", "mean_pool_coin_recv_bytes=42",
		"mean_validation_request_sent_bytes=33", "mean_validation_request_recv_bytes=43",
		"mean_aggregate_apdb_dispersal_sent_bytes=34", "mean_aggregate_apdb_dispersal_recv_bytes=44",
		"mean_candidate_relay_sent_bytes=35", "mean_candidate_relay_recv_bytes=45",
		"mean_decision_handoff_sent_bytes=36", "mean_decision_handoff_recv_bytes=46",
		"mean_new_aggregate_recovery_sent_bytes=37", "mean_new_aggregate_recovery_recv_bytes=47",
		"mean_new_aggregate_recovery_ms=7.50",
		"mean_new_share_exchange_sent_bytes=38", "mean_new_share_exchange_recv_bytes=48",
		"cv_failure_target=smoke", "cv_sampling_profile=smoke", "cv_sampling_policy=explicit-smoke",
		"cv_fault_fraction=2/7", "cv_total_failure_budget=none", "cv_per_event_failure_target=none",
		"cv_proposer_sample=3", "cv_validator_sample=3",
		"cv_validator_threshold=2", "cv_proposer_failure_bound=0",
		"cv_validator_soundness_failure_bound=1/7", "cv_validator_liveness_failure_bound=1/7",
		"cv_validator_combined_failure_bound=1/7", "cv_contributor_sampling_failure_bound=0",
		"cv_epoch_sampling_failure_bound=1/7", "cv_sampling_epochs=3", "cv_experiment_sampling_union_bound=3/7",
	} {
		if !strings.Contains(line, token) {
			t.Fatalf("CV benchmark output missing %q: %s", token, line)
		}
	}
}

func TestFormatBenchResultUsesConfiguredMaterializedARCLabel(t *testing.T) {
	line := formatBenchResult(benchResultInput{
		arcMode: "materialized",
		runs:    1,
	})
	if !strings.Contains(line, "arc_mode=materialized") {
		t.Fatalf("benchmark output mislabels materialized ARC: %s", line)
	}
}
