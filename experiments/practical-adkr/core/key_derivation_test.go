package core

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestNIZKDLog tests Schnorr NIZK proof of discrete logarithm.
func TestNIZKDLog(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N

	// Generate secret and public key
	x, _ := rand.Int(rand.Reader, order)
	pkX, pkY := curve.ScalarBaseMult(x.Bytes())
	pkBytes := elliptic.MarshalCompressed(curve, pkX, pkY)

	// Generate proof
	proof, err := ProveNIZKDLog(curve, x, pkBytes)
	if err != nil {
		t.Fatalf("ProveNIZKDLog failed: %v", err)
	}

	// Verify valid proof
	if !VerifyNIZKDLog(curve, pkBytes, proof) {
		t.Fatal("valid NIZK dLog proof failed verification")
	}

	// Verify with wrong public key should fail
	wrongX, _ := rand.Int(rand.Reader, order)
	wrongPKx, wrongPKy := curve.ScalarBaseMult(wrongX.Bytes())
	wrongPK := elliptic.MarshalCompressed(curve, wrongPKx, wrongPKy)
	if VerifyNIZKDLog(curve, wrongPK, proof) {
		t.Fatal("NIZK dLog proof verified under wrong public key")
	}

	t.Log("TestNIZKDLog PASSED")
}

// TestNIZKDHTuple tests NIZK proof of DH tuple.
func TestNIZKDHTuple(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N

	// g, h are two generators
	gX, gY := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	gBytes := elliptic.MarshalCompressed(curve, gX, gY)

	hScalar, _ := rand.Int(rand.Reader, order)
	hX, hY := curve.ScalarBaseMult(hScalar.Bytes())
	hBytes := elliptic.MarshalCompressed(curve, hX, hY)

	// Secret x, u = g^x, v = h^x
	x, _ := rand.Int(rand.Reader, order)
	uX, uY := curve.ScalarMult(gX, gY, x.Bytes())
	uBytes := elliptic.MarshalCompressed(curve, uX, uY)
	vX, vY := curve.ScalarMult(hX, hY, x.Bytes())
	vBytes := elliptic.MarshalCompressed(curve, vX, vY)

	// Prove
	proof, err := ProveNIZKDHTuple(curve, x, gBytes, hBytes, uBytes, vBytes)
	if err != nil {
		t.Fatalf("ProveNIZKDHTuple failed: %v", err)
	}

	// Verify valid
	if !VerifyNIZKDHTuple(curve, gBytes, hBytes, uBytes, vBytes, proof) {
		t.Fatal("valid DH tuple proof failed verification")
	}

	// Verify with wrong v should fail
	wrongV, _ := rand.Int(rand.Reader, order)
	wrongVx, wrongVy := curve.ScalarBaseMult(wrongV.Bytes())
	wrongVBytes := elliptic.MarshalCompressed(curve, wrongVx, wrongVy)
	if VerifyNIZKDHTuple(curve, gBytes, hBytes, uBytes, wrongVBytes, proof) {
		t.Fatal("DH tuple proof verified with wrong v")
	}

	t.Log("TestNIZKDHTuple PASSED")
}

// TestLagrangeInterpolation tests Lagrange interpolation of a polynomial.
func TestLagrangeInterpolation(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N

	// Create a degree-2 polynomial: f(x) = s + a1*x + a2*x^2
	s, _ := rand.Int(rand.Reader, order)
	a1, _ := rand.Int(rand.Reader, order)
	a2, _ := rand.Int(rand.Reader, order)
	coeffs := []*big.Int{s, a1, a2}

	// Evaluate at points 1, 2, 3 (need threshold=3 shares)
	threshold := 3
	evalPoints := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	shares := make([]*big.Int, threshold)
	for i, x := range evalPoints {
		shares[i] = evalPoly(coeffs, x, order)
	}

	// Reconstruct f(0) = s using Lagrange interpolation
	reconstructed := new(big.Int)
	for i := 0; i < threshold; i++ {
		lambda := LagrangeCoefficient(evalPoints, i, order)
		term := new(big.Int).Mul(lambda, shares[i])
		term.Mod(term, order)
		reconstructed.Add(reconstructed, term)
		reconstructed.Mod(reconstructed, order)
	}

	if reconstructed.Cmp(s) != 0 {
		t.Fatalf("Lagrange interpolation failed: got %s, want %s", reconstructed, s)
	}

	t.Log("TestLagrangeInterpolation PASSED")
}

// TestDeriveThresholdPK tests full threshold public key derivation.
func TestDeriveThresholdPK(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N

	// Secret polynomial: f(x) = s + a*x (degree 1, threshold=2)
	s, _ := rand.Int(rand.Reader, order)
	a, _ := rand.Int(rand.Reader, order)
	coeffs := []*big.Int{s, a}

	// Expected aggregate PK: g^s
	expectedPKx, expectedPKy := curve.ScalarBaseMult(s.Bytes())
	expectedPK := elliptic.MarshalCompressed(curve, expectedPKx, expectedPKy)

	// Generate shares for nodes 0,1,2
	nodeIDs := []int{0, 1, 2}
	pkShares := make([]PublicKeyShare, len(nodeIDs))
	for i, nid := range nodeIDs {
		x := big.NewInt(int64(nid + 1))
		share := evalPoly(coeffs, x, order)

		pks, err := GeneratePKShareWithProof(curve, nid, share)
		if err != nil {
			t.Fatalf("GeneratePKShareWithProof failed for node %d: %v", nid, err)
		}
		pkShares[i] = *pks
	}

	// Derive threshold PK (only need threshold=2 of 3 shares)
	derivedPK, err := DeriveThresholdPK(curve, pkShares, 2)
	if err != nil {
		t.Fatalf("DeriveThresholdPK failed: %v", err)
	}

	if !equalCommit(derivedPK, expectedPK) {
		t.Fatal("derived threshold PK does not match expected g^s")
	}

	t.Log("TestDeriveThresholdPK PASSED")
}
