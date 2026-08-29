package core

import "testing"

func TestTBLSSigner_SignVerifyRecover(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatalf("GenerateTBLSKeyBundle failed: %v", err)
	}
	signers := make([]ThresholdSigner, n)
	for i := 0; i < n; i++ {
		s, sErr := NewTBLSSigner(i, bundle)
		if sErr != nil {
			t.Fatalf("NewTBLSSigner(%d) failed: %v", i, sErr)
		}
		signers[i] = s
	}

	msg := []byte("tbls-msg")
	shares := make(map[int][]byte)
	for i := 0; i < n; i++ {
		sig, sErr := signers[i].Sign("EQ_COIN_SHARE", msg)
		if sErr != nil {
			t.Fatalf("Sign(%d) failed: %v", i, sErr)
		}
		if !signers[0].Verify(i, "EQ_COIN_SHARE", msg, sig) {
			t.Fatalf("Verify share failed for %d", i)
		}
		shares[i] = sig
	}

	combined, err := signers[0].Recover("EQ_COIN_SHARE", msg, shares)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if !signers[0].VerifyRecovered("EQ_COIN_SHARE", msg, combined) {
		t.Fatalf("VerifyRecovered failed")
	}
}
