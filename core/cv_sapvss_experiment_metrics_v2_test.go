package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVDealerPayloadResponseWithoutValidationMaterial(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{ctx: context.Background()}
	instance := bytes.Repeat([]byte{7}, 32)
	payload := []byte("payload")
	response := service.dealerPayloadResponseV2(instance, payload)
	if len(response) == 0 {
		t.Fatal("dealer response was not encoded without optional validation material")
	}
	decoded, err := cvDecodeAPDBPayloadResponseV2(response, 1024)
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("dealer response decode err=%v payload=%q", err, decoded.Payload)
	}
}

func TestCVDealerPayloadCompressionRollbackUsesLegacyWire(t *testing.T) {
	t.Setenv("RLADKR_COMPONENT_PAYLOAD_COMPRESSION", "off")
	service := &cvAPDBNetworkServiceV2{ctx: context.Background()}
	instance := bytes.Repeat([]byte{8}, 32)
	payload := bytes.Repeat([]byte("duplicate-canonical-block"), 1024)
	response := service.dealerPayloadResponseV2(instance, payload)
	legacy, err := cvAPDBPayloadResponseV2CanonicalBytes(&cvAPDBPayloadResponseV2{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil || !bytes.Equal(response, legacy) {
		t.Fatalf("compression rollback did not use legacy wire: err=%v", err)
	}
}

func TestCVServiceExperimentMetricsSeparateRecoveryPurposes(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{}
	service.recordRecoveryBytesV2(cvRecoveryProposerCatalogV2, true, 11)
	service.recordRecoveryBytesV2(cvRecoveryProposerCatalogV2, false, 12)
	service.recordRecoveryLatencyV2(cvRecoveryProposerCatalogV2, 13*time.Millisecond)
	service.experimentMu.Lock()
	service.experimentMetrics.proposerCatalogVerificationLatency = 14 * time.Millisecond
	service.experimentMu.Unlock()
	service.recordRecoveryBytesV2(cvRecoveryValidatorComponentV2, true, 21)
	service.recordRecoveryBytesV2(cvRecoveryValidatorComponentV2, false, 22)
	service.recordRecoveryLatencyV2(cvRecoveryValidatorComponentV2, 23*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryValidatorAggregateV2, true, 31)
	service.recordRecoveryBytesV2(cvRecoveryValidatorAggregateV2, false, 32)
	service.recordRecoveryLatencyV2(cvRecoveryValidatorAggregateV2, 33*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, true, 34)
	service.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, false, 35)
	service.recordRecoveryLatencyV2(cvRecoveryNewAggregateV2, 36*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryUnclassifiedV2, true, 100)
	service.recordRecoveryLatencyV2(cvRecoveryUnclassifiedV2, time.Second)
	service.recordCertificateFormationV2(cvCertificateARCV2, 41*time.Millisecond)
	service.recordCertificateFormationV2(cvCertificateValidationV2, 42*time.Millisecond)
	service.recordCertificateFormationV2(cvCertificateDecisionV2, 43*time.Millisecond)
	service.recordComponentRecoveryResponseSentV2(51, 52, 53)
	service.recordComponentRecoveryLateRecvBytesV2(54)
	service.experimentMu.Lock()
	service.experimentMetrics.componentDirectPayloadHits = 55
	service.experimentMetrics.componentFragmentRecoveries = 56
	service.experimentMu.Unlock()

	metrics := service.experimentMetricsV2()
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
	metrics := cvServiceExperimentMetricsV2{
		componentDispersalSentBytes: 11, componentDispersalRecvBytes: 12,
		aggregateDispersalSentBytes: 13, aggregateDispersalRecvBytes: 14,
		newAggregateRecoverySentBytes: 15, newAggregateRecoveryRecvBytes: 16,
		tagSentBytes: map[string]uint64{
			cvTagAggregateARCShareV2: 20,
			cvTagCoinShareV2:         21, cvTagValidationRequestV2: 22, cvTagCertifiedCandidateV2: 23,
			cvTagCertifiedCandidateACKV2: 26, cvTagCertifiedCandidateACKProbeV2: 27,
			cvTagHandoffV2: 24, cvTagAggregateShareV2: 25, cvTagAPDBStoreV2: 999,
		},
		tagRecvBytes: map[string]uint64{
			cvTagAggregateARCShareV2: 30,
			cvTagPoolOfferV2:         31, cvTagValidationSignatureV2: 32, cvTagCertifiedCandidateV2: 33,
			cvTagCertifiedCandidateACKV2: 36, cvTagCertifiedCandidateACKProbeV2: 37,
			cvTagDecisionShareV2: 34, cvTagAggregateShareV2: 35, cvTagAPDBStoreV2: 999,
		},
	}
	cvAddCostBreakdownV2(sent, recv, metrics)
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
