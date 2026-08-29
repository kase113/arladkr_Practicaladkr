package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVDealerPayloadResponseWithoutValidationMaterial(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{ctx: context.Background()}
	instance := bytes.Repeat([]byte{7}, 32)
	payload := []byte("payload")
	response := service.dealerPayloadResponseScalar(instance, payload)
	if len(response) == 0 {
		t.Fatal("dealer response was not encoded without optional validation material")
	}
	decoded, err := cvDecodeAPDBPayloadResponseScalar(response, 1024)
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("dealer response decode err=%v payload=%q", err, decoded.Payload)
	}
}

func TestCVDealerPayloadCompressionRollbackUsesLegacyWire(t *testing.T) {
	t.Setenv("RLADKR_COMPONENT_PAYLOAD_COMPRESSION", "off")
	service := &cvAPDBNetworkServiceScalar{ctx: context.Background()}
	instance := bytes.Repeat([]byte{8}, 32)
	payload := bytes.Repeat([]byte("duplicate-canonical-block"), 1024)
	response := service.dealerPayloadResponseScalar(instance, payload)
	legacy, err := cvAPDBPayloadResponseScalarCanonicalBytes(&cvAPDBPayloadResponseScalar{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil || !bytes.Equal(response, legacy) {
		t.Fatalf("compression rollback did not use legacy wire: err=%v", err)
	}
}

func TestCVServiceExperimentMetricsSeparateRecoveryPurposes(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{}
	service.recordRecoveryBytesScalar(cvRecoveryProposerCatalogScalar, true, 11)
	service.recordRecoveryBytesScalar(cvRecoveryProposerCatalogScalar, false, 12)
	service.recordRecoveryLatencyScalar(cvRecoveryProposerCatalogScalar, 13*time.Millisecond)
	service.experimentMu.Lock()
	service.experimentMetrics.proposerCatalogVerificationLatency = 14 * time.Millisecond
	service.experimentMu.Unlock()
	service.recordRecoveryBytesScalar(cvRecoveryValidatorComponentScalar, true, 21)
	service.recordRecoveryBytesScalar(cvRecoveryValidatorComponentScalar, false, 22)
	service.recordRecoveryLatencyScalar(cvRecoveryValidatorComponentScalar, 23*time.Millisecond)
	service.recordRecoveryBytesScalar(cvRecoveryValidatorAggregateScalar, true, 31)
	service.recordRecoveryBytesScalar(cvRecoveryValidatorAggregateScalar, false, 32)
	service.recordRecoveryLatencyScalar(cvRecoveryValidatorAggregateScalar, 33*time.Millisecond)
	service.recordRecoveryBytesScalar(cvRecoveryNewAggregateScalar, true, 34)
	service.recordRecoveryBytesScalar(cvRecoveryNewAggregateScalar, false, 35)
	service.recordRecoveryLatencyScalar(cvRecoveryNewAggregateScalar, 36*time.Millisecond)
	service.recordRecoveryBytesScalar(cvRecoveryUnclassifiedScalar, true, 100)
	service.recordRecoveryLatencyScalar(cvRecoveryUnclassifiedScalar, time.Second)
	service.recordCertificateFormationScalar(cvCertificateARCScalar, 41*time.Millisecond)
	service.recordCertificateFormationScalar(cvCertificateValidationScalar, 42*time.Millisecond)
	service.recordCertificateFormationScalar(cvCertificateDecisionScalar, 43*time.Millisecond)
	service.recordComponentRecoveryResponseSentScalar(51, 52, 53)
	service.recordComponentRecoveryLateRecvBytesScalar(54)
	service.experimentMu.Lock()
	service.experimentMetrics.componentDirectPayloadHits = 55
	service.experimentMetrics.componentFragmentRecoveries = 56
	service.experimentMu.Unlock()

	metrics := service.experimentMetricsScalar()
	if metrics.proposerRecoverySentBytes != 11 || metrics.proposerRecoveryRecvBytes != 12 ||
		metrics.proposerRecoveryLatency != 13*time.Millisecond ||
		metrics.proposerCatalogVerificationLatency != 14*time.Millisecond {
		t.Fatalf("proposer recovery metrics=%+v", metrics)
	}
	if metrics.validatorComponentRecoverySentBytes != 21 || metrics.validatorComponentRecoveryRecvBytes != 22 ||
		metrics.validatorComponentRecoveryLatency != 23*time.Millisecond ||
		metrics.validatorAggregateRecoverySentBytes != 31 || metrics.validatorAggregateRecoveryRecvBytes != 32 ||
		metrics.validatorAggregateRecoveryLatency != 33*time.Millisecond ||
		metrics.newAggregateRecoverySentBytes != 34 || metrics.newAggregateRecoveryRecvBytes != 35 ||
		metrics.newAggregateRecoveryLatency != 36*time.Millisecond {
		t.Fatalf("validator recovery metrics=%+v", metrics)
	}
	if metrics.arcFormationLatency != 41*time.Millisecond ||
		metrics.validationCertificateLatency != 42*time.Millisecond ||
		metrics.decisionCertificateLatency != 43*time.Millisecond {
		t.Fatalf("certificate formation metrics=%+v", metrics)
	}
	if metrics.dealerPayloadSentBytes != 51 || metrics.dealerHintSentBytes != 52 ||
		metrics.holderFragmentSentBytes != 53 || metrics.componentRecoveryLateRecvBytes != 54 ||
		metrics.componentDirectPayloadHits != 55 || metrics.componentFragmentRecoveries != 56 {
		t.Fatalf("component recovery profile metrics=%+v", metrics)
	}
}

func TestCVAddCostBreakdownMapsProtocolTerms(t *testing.T) {
	sent := make(map[string]uint64)
	recv := make(map[string]uint64)
	metrics := cvServiceExperimentMetricsScalar{
		componentDispersalSentBytes: 11, componentDispersalRecvBytes: 12,
		aggregateDispersalSentBytes: 13, aggregateDispersalRecvBytes: 14,
		newAggregateRecoverySentBytes: 15, newAggregateRecoveryRecvBytes: 16,
		tagSentBytes: map[string]uint64{
			cvTagAggregateARCShareScalar: 20,
			cvTagCoinShareScalar:         21, cvTagValidationRequestScalar: 22, cvTagCertifiedCandidateScalar: 23,
			cvTagCertifiedCandidateACKScalar: 26, cvTagCertifiedCandidateACKProbeScalar: 27,
			cvTagHandoffScalar: 24, cvTagAggregateShareScalar: 25, cvTagAPDBStoreScalar: 999,
		},
		tagRecvBytes: map[string]uint64{
			cvTagAggregateARCShareScalar: 30,
			cvTagPoolOfferScalar:         31, cvTagValidationSignatureScalar: 32, cvTagCertifiedCandidateScalar: 33,
			cvTagCertifiedCandidateACKScalar: 36, cvTagCertifiedCandidateACKProbeScalar: 37,
			cvTagDecisionShareScalar: 34, cvTagAggregateShareScalar: 35, cvTagAPDBStoreScalar: 999,
		},
	}
	cvAddCostBreakdownScalar(sent, recv, metrics)
	for name, want := range map[string]uint64{
		"component_apdb_dispersal": 11, "aggregate_apdb_dispersal": 13,
		"new_aggregate_recovery": 15, "arc_share": 20, "pool_coin": 21, "validation_request": 22,
		"candidate_relay": 76, "decision_handoff": 24, "new_share_exchange": 25,
	} {
		if sent[name] != want {
			t.Fatalf("sent %s=%d want %d", name, sent[name], want)
		}
	}
	for name, want := range map[string]uint64{
		"component_apdb_dispersal": 12, "aggregate_apdb_dispersal": 14,
		"new_aggregate_recovery": 16, "arc_share": 30, "pool_coin": 31, "validation_request": 32,
		"candidate_relay": 106, "decision_handoff": 34, "new_share_exchange": 35,
	} {
		if recv[name] != want {
			t.Fatalf("recv %s=%d want %d", name, recv[name], want)
		}
	}
}
