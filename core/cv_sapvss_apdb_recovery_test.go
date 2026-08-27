package core

import (
	"bytes"
	"errors"
	"testing"
)

func TestCVAPDBPayloadResponseV2TransportCompressionRoundTrip(t *testing.T) {
	instance := bytes.Repeat([]byte{0x42}, 32)
	block := make([]byte, 5400)
	for i := range block {
		block[i] = byte((i*131 + 17) % 251)
	}
	payload := append(append([]byte(nil), block...), block...)
	response := &cvAPDBPayloadResponseV2{InstanceDigest: instance, Payload: payload}
	legacy, err := cvAPDBPayloadResponseV2CanonicalBytes(response)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAPDBPayloadResponseV2TransportBytes(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) >= len(legacy) {
		t.Fatalf("transport compression did not reduce duplicated payload: compressed=%d legacy=%d", len(wire), len(legacy))
	}
	decoded, err := cvDecodeAPDBPayloadResponseV2(wire, len(payload))
	if err != nil || !bytes.Equal(decoded.InstanceDigest, instance) || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("compressed payload round trip failed: err=%v", err)
	}
	if _, err := cvDecodeAPDBPayloadResponseV2(wire[:len(wire)-1], len(payload)); err == nil {
		t.Fatal("accepted truncated compressed payload response")
	}
}

func TestCVAPDBRecoveryCollectorV2RequestsAllHoldersAndReconstructs(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	payload := []byte("validated all-holder APDB recovery")
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("recovery collector"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvAPDBStoredStatementV2(instance, encoded.root)
	if err != nil {
		t.Fatal(err)
	}
	lock := &cvAPDBLockV2{InstanceDigest: instance, Root: encoded.root,
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, public.APDBSigner, public.OldCommittee, cvAPDBStoredDomain, statement)}
	bindingChecked := false
	collector, err := newCVAPDBRecoveryCollectorV2(lock, public.OldCommittee, public.Params.recoveryThreshold,
		encoded.shardBytes, 1024, public.APDBSigner, func(got []byte) error {
			if !bytes.Equal(got, payload) {
				t.Fatal("binding check received the wrong payload")
			}
			bindingChecked = true
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(collector.RequestRecipients(), public.OldCommittee) {
		t.Fatal("APDB recovery did not target every old holder")
	}
	if _, err := collector.Recover(); err == nil {
		t.Fatal("recovered before collecting the threshold")
	}
	for index := 0; index < public.Params.recoveryThreshold; index++ {
		wire, err := cvAPDBStoreV2CanonicalBytes(&encoded.stores[index], len(public.OldCommittee), encoded.shardBytes)
		if err != nil {
			t.Fatal(err)
		}
		complete, err := collector.AddStore(public.OldCommittee[index], wire)
		if err != nil || complete != (index+1 == public.Params.recoveryThreshold) {
			t.Fatalf("add APDB recovery response %d: complete=%v err=%v", index, complete, err)
		}
		if index == 0 {
			if _, err := collector.AddStore(public.OldCommittee[index], wire); err != nil {
				t.Fatalf("matching APDB response was not idempotent: %v", err)
			}
		}
	}
	recovered, direct, err := collector.recoverWithSource()
	if err != nil || direct || !bytes.Equal(recovered, payload) || !bindingChecked {
		t.Fatalf("recover APDB payload: binding=%v err=%v", bindingChecked, err)
	}
	collector.bindingCheck = func([]byte) error { return errors.New("rejected payload binding") }
	if _, _, err := collector.recoverWithSource(); err == nil {
		t.Fatal("APDB recovery accepted a payload rejected by its binding check")
	}
}

func TestCVAPDBRecoveryCollectorV2ReportsAuthenticatedPayloadSource(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	payload := []byte("authenticated payload fast path")
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("payload source"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvAPDBStoredStatementV2(instance, encoded.root)
	if err != nil {
		t.Fatal(err)
	}
	lock := &cvAPDBLockV2{InstanceDigest: instance, Root: encoded.root,
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, public.APDBSigner, public.OldCommittee, cvAPDBStoredDomain, statement)}
	collector, err := newCVAPDBRecoveryCollectorV2(lock, public.OldCommittee, public.Params.recoveryThreshold,
		encoded.shardBytes, 1024, public.APDBSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := cvAPDBPayloadResponseV2CanonicalBytes(&cvAPDBPayloadResponseV2{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if complete, err := collector.AddPayload(public.OldCommittee[0], response); err != nil || !complete {
		t.Fatalf("add payload response: complete=%v err=%v", complete, err)
	}
	decoded, err := cvDecodeAPDBPayloadResponseV2(response, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if complete, err := collector.addDecodedPayload(decoded); err != nil || !complete {
		t.Fatalf("add decoded payload response: complete=%v err=%v", complete, err)
	}
	wrongInstance := *decoded
	wrongInstance.InstanceDigest = append([]byte(nil), decoded.InstanceDigest...)
	wrongInstance.InstanceDigest[0] ^= 1
	if _, err := collector.addDecodedPayload(&wrongInstance); err == nil {
		t.Fatal("accepted decoded payload response for another APDB instance")
	}
	for i := range response {
		response[i] ^= 0xff
	}
	recovered, direct, err := collector.recoverWithSource()
	if err != nil || !direct || !bytes.Equal(recovered, payload) {
		t.Fatalf("payload source direct=%v err=%v payload=%q", direct, err, recovered)
	}
}

func TestCVAPDBRecoveryCollectorV2OwnedPayloadTransfer(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	payload := []byte("owned payload response")
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("owned payload"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvAPDBStoredStatementV2(instance, encoded.root)
	if err != nil {
		t.Fatal(err)
	}
	lock := &cvAPDBLockV2{InstanceDigest: instance, Root: encoded.root,
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, public.APDBSigner, public.OldCommittee, cvAPDBStoredDomain, statement)}
	collector, err := newCVAPDBRecoveryCollectorV2(lock, public.OldCommittee, public.Params.recoveryThreshold,
		encoded.shardBytes, 1024, public.APDBSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	hints := []byte(nil)
	response := &cvAPDBPayloadResponseV2{InstanceDigest: instance, Payload: payload, Hints: hints}
	if complete, err := collector.addDecodedPayloadOwned(response); err != nil || !complete {
		t.Fatalf("owned payload response: complete=%v err=%v", complete, err)
	}
	recovered, direct, err := collector.recoverWithSource()
	if err != nil || !direct || &recovered[0] != &payload[0] {
		t.Fatalf("owned payload was copied or rejected: direct=%v err=%v", direct, err)
	}
}

func TestCVAPDBRecoveryCollectorV2RejectsSenderAndStoreMutations(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	collector, err := newCVAPDBRecoveryCollectorV2(&object.ARC, public.OldCommittee, public.Params.recoveryThreshold,
		32, 1024, public.APDBSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoster := append([]int(nil), public.OldCommittee...)
	for i := range wrongRoster {
		wrongRoster[i] += 100
	}
	if _, err := newCVAPDBRecoveryCollectorV2(&object.ARC, wrongRoster, public.Params.recoveryThreshold,
		32, 1024, public.APDBSigner, nil); err == nil {
		t.Fatal("accepted a holder roster different from the APDB signer roster")
	}
	if _, err := collector.AddStore(9999, []byte("not a store")); err == nil {
		t.Fatal("accepted APDB response from a non-holder")
	}

	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("sender binding"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, []byte("sender-bound response"), public.Params.recoveryThreshold,
		len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := cvAPDBStoredStatementV2(instance, encoded.root)
	lock := &cvAPDBLockV2{InstanceDigest: instance, Root: encoded.root,
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, public.APDBSigner, public.OldCommittee, cvAPDBStoredDomain, statement)}
	collector, err = newCVAPDBRecoveryCollectorV2(lock, public.OldCommittee, public.Params.recoveryThreshold,
		encoded.shardBytes, 1024, public.APDBSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAPDBStoreV2CanonicalBytes(&encoded.stores[0], len(public.OldCommittee), encoded.shardBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.AddStore(public.OldCommittee[1], wire); err == nil {
		t.Fatal("accepted a store whose index did not match the authenticated sender")
	}
	if _, err := collector.AddStore(public.OldCommittee[0], append(append([]byte(nil), wire...), 0)); err == nil {
		t.Fatal("accepted a store with trailing bytes")
	}
}

func TestCVAggregateRecoveryCollectorV2RequiresDecisionAuthorization(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	statement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	handoff := cvHandoffV2{ContextDigest: public.ContextDigest, Header: object.Header, ARC: object.ARC,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.OldCommittee,
			cvDecisionCertificateV2Domain, statement)}
	request, err := cvAggregateRecoveryRequestV2CanonicalBytes(&cvAggregateRecoveryRequestV2{Handoff: handoff})
	if err != nil {
		t.Fatal(err)
	}
	collector, err := newCVAggregateRecoveryCollectorV2(request, public.ContextDigest, public.OldCommittee,
		public.Params.recoveryThreshold, 32, 1024, public.APDBSigner, public.ControlSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(collector.RequestWire(), request) || !equalInts(collector.RequestRecipients(), public.OldCommittee) {
		t.Fatal("aggregate recovery collector did not retain the authorized all-holder request")
	}
	bad := append([]byte(nil), request...)
	bad[len(bad)-1] ^= 1
	if _, err := newCVAggregateRecoveryCollectorV2(bad, public.ContextDigest, public.OldCommittee,
		public.Params.recoveryThreshold, 32, 1024, public.APDBSigner, public.ControlSigner, nil); err == nil {
		t.Fatal("created aggregate recovery collector without a valid DecCert")
	}
}
