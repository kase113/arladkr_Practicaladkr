package core

import (
	"bytes"
	"testing"
)

func TestCVHandoffV2CarriesOnlyDecisionCertifiedHeaderAndARC(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	statement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.ValidatorKeys.memberOrder,
		cvDecisionCertificateV2Domain, statement)
	handoff := &cvHandoffV2{ContextDigest: append([]byte(nil), public.ContextDigest...), Header: object.Header, ARC: object.ARC, DecCert: decCert}
	if err := cvVerifyHandoffV2(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner); err != nil {
		t.Fatalf("verify V2 handoff: %v", err)
	}
	wire, err := cvHandoffV2CanonicalBytes(handoff)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeHandoffV2(wire)
	if err != nil || !bytes.Equal(decoded.DecCert, decCert) {
		t.Fatalf("V2 handoff codec: %v", err)
	}
	if len(wire) >= len(mustAgreementWireV2(t, object, public)) {
		t.Fatal("compact handoff is not smaller than the old-committee agreement object")
	}
	if _, err := cvDecodeHandoffV2(append(append([]byte(nil), wire...), 0)); err == nil {
		t.Fatal("accepted V2 handoff with trailing bytes")
	}
}

func TestCVHandoffV2RejectsDecisionAndARCMutations(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	statement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.ValidatorKeys.memberOrder,
		cvDecisionCertificateV2Domain, statement)
	handoff := &cvHandoffV2{ContextDigest: public.ContextDigest, Header: object.Header, ARC: object.ARC, DecCert: decCert}
	badCert := *handoff
	badCert.DecCert = append([]byte(nil), decCert...)
	badCert.DecCert[len(badCert.DecCert)-1] ^= 1
	if err := cvVerifyHandoffV2(&badCert, public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("accepted mutated V2 DecCert")
	}
	badARC := *handoff
	badARC.ARC = handoff.ARC
	badARC.ARC.Root = append([]byte(nil), handoff.ARC.Root...)
	badARC.ARC.Root[0] ^= 1
	if _, err := cvHandoffV2CanonicalBytes(&badARC); err == nil {
		t.Fatal("encoded handoff with ARC/header mismatch")
	}
	wrongContext := append([]byte(nil), public.ContextDigest...)
	wrongContext[0] ^= 1
	if err := cvVerifyHandoffV2(handoff, wrongContext, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("accepted V2 handoff under a different context")
	}
	if err := cvVerifyHandoffV2(handoff, public.ContextDigest, public.ControlSigner, public.APDBSigner); err == nil {
		t.Fatal("accepted swapped APDB and control signers")
	}
}

func TestCVAggregateRecoveryRequestV2RequiresValidDecCert(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	statement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.OldCommittee,
		cvDecisionCertificateV2Domain, statement)
	request := &cvAggregateRecoveryRequestV2{Handoff: cvHandoffV2{
		ContextDigest: public.ContextDigest, Header: object.Header, ARC: object.ARC, DecCert: decCert,
	}}
	wire, err := cvAggregateRecoveryRequestV2CanonicalBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := cvAuthorizeAggregateRecoveryRequestV2(wire, public.ContextDigest, public.APDBSigner, public.ControlSigner)
	if err != nil || !bytes.Equal(authorized.ARC.InstanceDigest, object.ARC.InstanceDigest) {
		t.Fatalf("authorize V2 aggregate recovery: %v", err)
	}
	bad := *request
	bad.Handoff = request.Handoff
	bad.Handoff.DecCert = append([]byte(nil), request.Handoff.DecCert...)
	bad.Handoff.DecCert[len(bad.Handoff.DecCert)-1] ^= 1
	badWire, err := cvAggregateRecoveryRequestV2CanonicalBytes(&bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvAuthorizeAggregateRecoveryRequestV2(badWire, public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("authorized aggregate recovery with a mutated DecCert")
	}
	if _, err := cvAuthorizeAggregateRecoveryRequestV2(append(wire, 0), public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("authorized aggregate recovery with trailing request bytes")
	}
}

func mustAgreementWireV2(t *testing.T, object *cvAgreementObjectV2, public cvAgreementPublicContextV2) []byte {
	t.Helper()
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
