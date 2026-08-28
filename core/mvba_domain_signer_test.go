package core

import (
	"bytes"
	"testing"
)

func TestMVBADomainSignerRoutesHighAndLowThresholdCertificates(t *testing.T) {
	members := []int{0, 1, 2, 3}
	high, err := newTBLSThresholdSigner(
		members, 3, deterministicStream("mvba-domain-high-test", []byte("seed")),
	)
	if err != nil {
		t.Fatal(err)
	}
	low, err := newTBLSThresholdSigner(
		members, 2, deterministicStream("mvba-domain-low-test", []byte("seed")),
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := &mvbaDomainSigner{member: 0, high: high, low: low}
	for domain, want := range map[string]int{
		"PD_STORED": 3, "PD_LOCKED": 3, "ACS_DIFFUSE": 3,
		"PD_QUIT_READY": 2, "EQ_COIN_SHARE": 2,
	} {
		if got := signer.Threshold(domain); got != want {
			t.Fatalf("domain %s threshold=%d want=%d", domain, got, want)
		}
	}

	digest := hashBytes([]byte("mvba domain certificate"))
	shares := make(map[int][]byte, signer.Threshold("PD_STORED"))
	for _, member := range members[:signer.Threshold("PD_STORED")] {
		memberSigner := &mvbaDomainSigner{member: member, high: high, low: low}
		share, signErr := memberSigner.Sign("PD_STORED", digest)
		if signErr != nil || !signer.Verify(member, "PD_STORED", digest, share) {
			t.Fatalf("high-threshold share %d: %v", member, signErr)
		}
		shares[member] = share
	}
	certificate, err := signer.Recover("PD_STORED", digest, shares)
	if err != nil || !signer.VerifyRecovered("PD_STORED", digest, certificate) {
		t.Fatalf("recover high-threshold MVBA certificate: %v", err)
	}
	if signer.VerifyRecovered("PD_QUIT_READY", digest, certificate) {
		t.Fatal("high-threshold PD certificate verified under low-threshold QuitPD domain")
	}
	mutated := append([]byte(nil), certificate...)
	mutated[len(mutated)-1] ^= 1
	if bytes.Equal(mutated, certificate) || signer.VerifyRecovered("PD_STORED", digest, mutated) {
		t.Fatal("mutated MVBA certificate verified")
	}
	if signer.Threshold("UNKNOWN_MVBA_DOMAIN") != 0 ||
		signer.Verify(0, "UNKNOWN_MVBA_DOMAIN", digest, shares[0]) ||
		signer.VerifyRecovered("UNKNOWN_MVBA_DOMAIN", digest, certificate) {
		t.Fatal("unknown MVBA domain was routed to a threshold signer")
	}
	if _, err := signer.Sign("UNKNOWN_MVBA_DOMAIN", digest); err == nil {
		t.Fatal("unknown MVBA domain produced a signature share")
	}
	if _, err := signer.Recover("UNKNOWN_MVBA_DOMAIN", digest, shares); err == nil {
		t.Fatal("unknown MVBA domain recovered a certificate")
	}
}
