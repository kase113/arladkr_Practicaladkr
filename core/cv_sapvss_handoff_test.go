package core

import (
	"bytes"
	"testing"
)

func TestCVHandoffScalarCarriesOnlyDecisionCertifiedHeaderAndARC(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	statement, err := cvDecisionStatementScalar(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateScalarForTest(t, public.ControlSigner, public.ValidatorKeys.memberOrder,
		cvDecisionCertificateScalarDomain, statement)
	handoff := &cvHandoffScalar{ContextDigest: append([]byte(nil), public.ContextDigest...), Header: object.Header, ARC: object.ARC, DecCert: decCert}
	if err := cvVerifyHandoffScalar(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner); err != nil {
		t.Fatalf("verify V2 handoff: %v", err)
	}
	wire, err := cvHandoffScalarCanonicalBytes(handoff)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeHandoffScalar(wire)
	if err != nil || !bytes.Equal(decoded.DecCert, decCert) {
		t.Fatalf("V2 handoff codec: %v", err)
	}
	if len(wire) >= len(mustAgreementWireScalar(t, object, public)) {
		t.Fatal("compact handoff is not smaller than the old-committee agreement object")
	}
	if _, err := cvDecodeHandoffScalar(append(append([]byte(nil), wire...), 0)); err == nil {
		t.Fatal("accepted V2 handoff with trailing bytes")
	}
}

func TestCVHandoffScalarRejectsDecisionAndARCMutations(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	statement, err := cvDecisionStatementScalar(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateScalarForTest(t, public.ControlSigner, public.ValidatorKeys.memberOrder,
		cvDecisionCertificateScalarDomain, statement)
	handoff := &cvHandoffScalar{ContextDigest: public.ContextDigest, Header: object.Header, ARC: object.ARC, DecCert: decCert}
	badCert := *handoff
	badCert.DecCert = append([]byte(nil), decCert...)
	badCert.DecCert[len(badCert.DecCert)-1] ^= 1
	if err := cvVerifyHandoffScalar(&badCert, public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("accepted mutated V2 DecCert")
	}
	badARC := *handoff
	badARC.ARC = handoff.ARC
	badARC.ARC.Root = append([]byte(nil), handoff.ARC.Root...)
	badARC.ARC.Root[0] ^= 1
	if _, err := cvHandoffScalarCanonicalBytes(&badARC); err == nil {
		t.Fatal("encoded handoff with ARC/header mismatch")
	}
	wrongContext := append([]byte(nil), public.ContextDigest...)
	wrongContext[0] ^= 1
	if err := cvVerifyHandoffScalar(handoff, wrongContext, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("accepted V2 handoff under a different context")
	}
	if err := cvVerifyHandoffScalar(handoff, public.ContextDigest, public.ControlSigner, public.APDBSigner); err == nil {
		t.Fatal("accepted swapped APDB and control signers")
	}
}

func TestCVAggregateRecoveryRequestScalarRequiresValidDecCert(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	statement, err := cvDecisionStatementScalar(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decCert := cvRecoverThresholdCertificateScalarForTest(t, public.ControlSigner, public.OldCommittee,
		cvDecisionCertificateScalarDomain, statement)
	request := &cvAggregateRecoveryRequestScalar{Handoff: cvHandoffScalar{
		ContextDigest: public.ContextDigest, Header: object.Header, ARC: object.ARC, DecCert: decCert,
	}}
	wire, err := cvAggregateRecoveryRequestScalarCanonicalBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := cvAuthorizeAggregateRecoveryRequestScalar(wire, public.ContextDigest, public.APDBSigner, public.ControlSigner)
	if err != nil || !bytes.Equal(authorized.ARC.InstanceDigest, object.ARC.InstanceDigest) {
		t.Fatalf("authorize V2 aggregate recovery: %v", err)
	}
	bad := *request
	bad.Handoff = request.Handoff
	bad.Handoff.DecCert = append([]byte(nil), request.Handoff.DecCert...)
	bad.Handoff.DecCert[len(bad.Handoff.DecCert)-1] ^= 1
	badWire, err := cvAggregateRecoveryRequestScalarCanonicalBytes(&bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvAuthorizeAggregateRecoveryRequestScalar(badWire, public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("authorized aggregate recovery with a mutated DecCert")
	}
	if _, err := cvAuthorizeAggregateRecoveryRequestScalar(append(wire, 0), public.ContextDigest, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("authorized aggregate recovery with trailing request bytes")
	}
}

func mustAgreementWireScalar(t *testing.T, object *cvAgreementObjectScalar, public cvAgreementPublicContextScalar) []byte {
	t.Helper()
	_, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectScalarCanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
