package core

import (
	"bytes"
	"testing"
)

func TestGenerateEd25519KeySetAndSigner(t *testing.T) {
	pub, priv, err := GenerateEd25519KeySet(4)
	if err != nil {
		t.Fatalf("GenerateEd25519KeySet failed: %v", err)
	}
	if len(pub) != 4 || len(priv) != 4 {
		t.Fatalf("unexpected keyset size: pub=%d priv=%d", len(pub), len(priv))
	}

	signers := make([]Signer, 4)
	for i := 0; i < 4; i++ {
		s, sErr := NewEd25519Signer(i, priv[i], pub)
		if sErr != nil {
			t.Fatalf("NewEd25519Signer(%d): %v", i, sErr)
		}
		signers[i] = s
	}

	msg := []byte("mvba-test-digest")
	sig, err := signers[2].Sign("SPBC_ECHO", msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}

	if !signers[0].Verify(2, "SPBC_ECHO", msg, sig) {
		t.Fatalf("verify should pass")
	}
	if signers[0].Verify(2, "SPBC_READY", msg, sig) {
		t.Fatalf("verify should fail for different domain")
	}
	if signers[0].Verify(1, "SPBC_ECHO", msg, sig) {
		t.Fatalf("verify should fail for wrong signer id")
	}
	if signers[0].Verify(2, "SPBC_ECHO", append([]byte(nil), msg...), append([]byte{1}, sig...)) {
		t.Fatalf("verify should fail for modified signature")
	}
	if !bytes.Equal(msg, []byte("mvba-test-digest")) {
		t.Fatalf("input message should not be mutated")
	}
}
