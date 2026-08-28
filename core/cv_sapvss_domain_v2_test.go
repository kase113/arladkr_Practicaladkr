package core

import (
	"bytes"
	"testing"
)

func TestCVV2CertificateDomainsAreDistinctAndNonInterchangeable(t *testing.T) {
	domains := []string{
		cvAPDBStoredDomain,
		cvPoolCertV2Domain,
		cvValidationCertificateV2Domain,
		cvDecisionCertificateV2Domain,
	}
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain == "" {
			t.Fatal("empty CV V2 certificate domain")
		}
		if _, duplicate := seen[domain]; duplicate {
			t.Fatalf("reused CV V2 certificate domain %q", domain)
		}
		seen[domain] = struct{}{}
	}

	object, public := cvAgreementObjectV2Fixture(t)
	poolStatement, err := cvPoolCertificateStatementV2(
		public.ContextDigest, object.Pool.ProposerID, object.Pool.Digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !public.ControlSigner.VerifyRecovered(cvPoolCertV2Domain, poolStatement, object.PoolCert.Certificate) {
		t.Fatal("valid PoolCert did not verify in its own domain")
	}
	if public.ControlSigner.VerifyRecovered(cvDecisionCertificateV2Domain, poolStatement, object.PoolCert.Certificate) {
		t.Fatal("PoolCert verified as a DecCert under the same control key")
	}

	decisionStatement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil {
		t.Fatal(err)
	}
	decisionCertificate := cvRecoverThresholdCertificateV2ForTest(
		t, public.ControlSigner, public.OldCommittee, cvDecisionCertificateV2Domain, decisionStatement,
	)
	if !public.ControlSigner.VerifyRecovered(cvDecisionCertificateV2Domain, decisionStatement, decisionCertificate) {
		t.Fatal("valid DecCert did not verify in its own domain")
	}
	if public.ControlSigner.VerifyRecovered(cvPoolCertV2Domain, decisionStatement, decisionCertificate) {
		t.Fatal("DecCert verified as a PoolCert under the same control key")
	}

	storedStatement, err := cvAPDBStoredStatementV2(object.ARC.InstanceDigest, object.ARC.Root)
	if err != nil {
		t.Fatal(err)
	}
	if !public.APDBSigner.VerifyRecovered(cvAPDBStoredDomain, storedStatement, object.ARC.Certificate) {
		t.Fatal("valid ARC did not verify in its own domain")
	}
	if public.APDBSigner.VerifyRecovered(cvPoolCertV2Domain, storedStatement, object.ARC.Certificate) {
		t.Fatal("ARC verified under the PoolCert domain")
	}
}

func TestCVV2ValidationOneShotRejectsConflictingStatement(t *testing.T) {
	reservations := make(map[int][]byte)
	first := hashBytes([]byte("first validation statement"))
	if !cvReserveValidationStatementV2(reservations, 7, first) {
		t.Fatal("failed to reserve the first validation statement")
	}
	if !cvReserveValidationStatementV2(reservations, 7, append([]byte(nil), first...)) {
		t.Fatal("same validation statement was not idempotent")
	}
	first[0] ^= 1
	if bytes.Equal(reservations[7], first) {
		t.Fatal("validation reservation aliased caller-owned bytes")
	}
	second := hashBytes([]byte("second validation statement"))
	if cvReserveValidationStatementV2(reservations, 7, second) {
		t.Fatal("reserved two validation statements for one proposer slot")
	}
	if !cvReserveValidationStatementV2(reservations, 8, second) {
		t.Fatal("reservation leaked across proposer slots")
	}
}
