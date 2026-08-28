package core

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func cvRandomCurvePointOutsideSubgroup(t *testing.T) bls12381.G1Affine {
	t.Helper()
	var x fp.Element
	for attempt := 0; attempt < 200; attempt++ {
		x.SetRandom()
		var ySquared, y fp.Element
		ySquared.Square(&x).Mul(&ySquared, &x)
		ySquared.Add(&ySquared, new(fp.Element).SetUint64(4))
		if y.Sqrt(&ySquared) == nil {
			continue
		}
		candidate := bls12381.G1Affine{X: x, Y: y}
		if candidate.IsInSubGroup() {
			continue
		}
		return candidate
	}
	t.Fatal("could not sample a curve point outside the prime-order subgroup")
	return bls12381.G1Affine{}
}

func TestCVDecodeG1UncheckedMatchesGnarkForSubgroupPoints(t *testing.T) {
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []bls12381.G1Affine{genG1, h} {
		encoded := point.Bytes()
		decoded, err := cvDecodeG1WireUnchecked(encoded[:])
		if err != nil {
			t.Fatal(err)
		}
		if !decoded.Equal(&point) {
			t.Fatal("unchecked decode diverged from gnark encoding")
		}
	}
	var infinity bls12381.G1Affine
	encoded := infinity.Bytes()
	decoded, err := cvDecodeG1WireUnchecked(encoded[:])
	if err != nil || !decoded.IsInfinity() {
		t.Fatal("unchecked decode broke infinity handling")
	}
}

func TestCVSubgroupBatchRejectsNonSubgroupPoints(t *testing.T) {
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	outsider := cvRandomCurvePointOutsideSubgroup(t)
	if err := cvAssertG1SubgroupBatch([]bls12381.G1Affine{genG1, outsider, h}); err == nil {
		t.Fatal("batch subgroup check accepted a point outside the order-r subgroup")
	}
	if err := cvAssertG1SubgroupBatch([]bls12381.G1Affine{genG1, h}); err != nil {
		t.Fatalf("batch subgroup check rejected valid points: %v", err)
	}
	if err := cvAssertG1SubgroupBatch(nil); err != nil {
		t.Fatal("empty batch must pass")
	}
	encoded := outsider.Bytes()
	if _, err := new(bls12381.G1Affine).SetBytes(encoded[:]); err == nil {
		t.Fatal("gnark reference accepted a non-subgroup point; test fixture is invalid")
	}
	decoded, err := cvDecodeG1WireUnchecked(encoded[:])
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(&outsider) {
		t.Fatal("unchecked decode did not reproduce the crafted point")
	}
}
