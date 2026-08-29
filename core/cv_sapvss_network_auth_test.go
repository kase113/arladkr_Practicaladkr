package core

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvNetworkAuthFixture(t *testing.T) *cvNetworkAuthenticator {
	t.Helper()
	signer, err := newTBLSThresholdSigner(
		[]int{0, 1, 2, 3}, 3, deterministicStream("cv-network-auth-test", []byte("fixture")),
	)
	if err != nil {
		t.Fatal(err)
	}
	var receiverSecret fr.Element
	receiverSecret.SetUint64(91)
	var receiverPublic bls12381.G1Affine
	receiverPublic.ScalarMultiplication(&genG1, receiverSecret.BigInt(new(big.Int)))
	auth, err := newCVNetworkAuthenticator(
		signer, []int{4}, []bls12381.G1Affine{receiverPublic}, map[int]fr.Element{4: receiverSecret},
	)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestCVNetworkAuthenticationBindsActorRouteAndBody(t *testing.T) {
	auth := cvNetworkAuthFixture(t)
	envelope, err := cvEncodeNetworkEnvelope("network-auth", 7, []byte("authenticated payload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		sender int
		tag    string
	}{
		{sender: 1, tag: cvTagComponentGet},
		{sender: 4, tag: apvssTagLaneACK},
	} {
		wire, err := auth.seal(test.sender, 2, test.tag, envelope)
		if err != nil {
			t.Fatalf("seal sender %d: %v", test.sender, err)
		}
		opened, err := auth.open(test.sender, 2, test.tag, wire)
		if err != nil || !bytes.Equal(opened, envelope) {
			t.Fatalf("open sender %d: payload=%x err=%v", test.sender, opened, err)
		}
		for name, open := range map[string]func() error{
			"sender":    func() error { _, err := auth.open(0, 2, test.tag, wire); return err },
			"recipient": func() error { _, err := auth.open(test.sender, 3, test.tag, wire); return err },
			"tag":       func() error { _, err := auth.open(test.sender, 2, cvTagComponentLeaf, wire); return err },
		} {
			if err := open(); err == nil {
				t.Fatalf("sender %d signature did not bind %s", test.sender, name)
			}
		}
		mutated := append([]byte(nil), wire...)
		mutated[8] ^= 1
		if _, err := auth.open(test.sender, 2, test.tag, mutated); err == nil {
			t.Fatalf("sender %d authenticated a mutated envelope", test.sender)
		}
	}
	if _, err := auth.seal(99, 2, cvTagComponentGet, envelope); err == nil {
		t.Fatal("unregistered actor produced a network signature")
	}
	if _, err := auth.open(1, 2, cvTagComponentGet, envelope); err == nil {
		t.Fatal("strict authentication accepted an unsigned envelope")
	}
}

func TestCVNetworkAuthenticationSupportsOverlappingCommitteeActor(t *testing.T) {
	signer, err := newTBLSThresholdSigner(
		[]int{0, 1, 2, 3}, 3, deterministicStream("cv-network-auth-overlap", []byte("fixture")),
	)
	if err != nil {
		t.Fatal(err)
	}
	var receiverSecret fr.Element
	receiverSecret.SetUint64(91)
	var receiverPublic bls12381.G1Affine
	receiverPublic.ScalarMultiplication(&genG1, receiverSecret.BigInt(new(big.Int)))
	auth, err := newCVNetworkAuthenticator(
		signer, []int{0}, []bls12381.G1Affine{receiverPublic}, map[int]fr.Element{0: receiverSecret},
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cvEncodeNetworkEnvelope("network-auth-overlap", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	oldWire, err := auth.seal(0, 1, cvTagComponentGet, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.open(0, 1, cvTagComponentGet, oldWire); err != nil {
		t.Fatalf("overlapping actor old-node role failed: %v", err)
	}
	receiverWire, err := auth.seal(0, 1, apvssTagLaneACK, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.open(0, 1, apvssTagLaneACK, receiverWire); err != nil {
		t.Fatalf("overlapping actor receiver role failed: %v", err)
	}
	if _, err := auth.open(0, 1, apvssTagLaneACK, oldWire); err == nil {
		t.Fatal("old-node signature was accepted as an overlapping receiver signature")
	}
	if _, err := auth.open(0, 1, cvTagComponentGet, receiverWire); err == nil {
		t.Fatal("receiver signature was accepted as an overlapping old-node signature")
	}
}
