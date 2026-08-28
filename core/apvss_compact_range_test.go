package core

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestAPVSSCompactInnerProductVectorVerifies(t *testing.T) {
	generators, err := apvssCompactRangeGeneratorsFor(4)
	if err != nil {
		t.Fatal(err)
	}
	a := []fr.Element{cvTestScalar(1), cvTestScalar(2), cvTestScalar(3), cvTestScalar(4)}
	b := []fr.Element{cvTestScalar(5), cvTestScalar(6), cvTestScalar(7), cvTestScalar(8)}
	prefix := hashBytes([]byte("ARL-APVSS/compact-range/cross-vector"), []byte{0, 1, 2, 3})
	inner := apvssCompactInnerProduct(a, b)
	p := apvssCompactPointSum(generators.g, a)
	p.Add(&p, pointPtr(apvssCompactPointSum(generators.h, b)))
	p.Add(&p, pointPtr(cvPointTimes(&generators.u, &inner)))
	proof, err := apvssProveCompactInnerProduct(
		prefix, generators.g, generators.h, generators.u, a, b,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyCompactInnerProduct(
		prefix, generators.g, generators.h, generators.u, p, &proof,
	); err != nil {
		t.Fatalf("deterministic inner-product vector rejected: %v", err)
	}
}

func apvssCompactRangeFixture(t testing.TB, values []uint64, bits int) ([]byte, []fr.Element, []bls12381.G1Affine) {
	t.Helper()
	statement := hashBytes([]byte("apvss-compact-range-test"), []byte{byte(bits), byte(len(values))})
	blindings := make([]fr.Element, len(values))
	commitments := make([]bls12381.G1Affine, len(values))
	for i := range values {
		var err error
		blindings[i], err = apvssRandomFr()
		if err != nil {
			t.Fatal(err)
		}
		commitments[i], err = apvssCompactRangeCommitment(values[i], blindings[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	return statement, blindings, commitments
}

func apvssCloneCompactRangeProofForTest(in *apvssCompactRangeProof) *apvssCompactRangeProof {
	if in == nil {
		return nil
	}
	out := *in
	out.inner.left = append([]bls12381.G1Affine(nil), in.inner.left...)
	out.inner.right = append([]bls12381.G1Affine(nil), in.inner.right...)
	return &out
}

func TestAPVSSCompactRangeProofV1(t *testing.T) {
	values := []uint64{0, 1, 255, 42, 7}
	statement, blindings, commitments := apvssCompactRangeFixture(t, values, 8)
	proof, err := apvssProveCompactRange(statement, commitments, values, blindings, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyCompactRange(statement, commitments, proof, 8); err != nil {
		t.Fatalf("valid aggregated range proof rejected: %v", err)
	}
	wire, err := apvssCompactRangeProofCanonicalBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) == 0 || len(proof.inner.left) != 6 {
		t.Fatalf("unexpected compact range proof size/rounds: %d/%d", len(wire), len(proof.inner.left))
	}
}

func TestAPVSSCompactRangeProofRejectsMutationV1(t *testing.T) {
	values := []uint64{0, 1, 2, 3}
	statement, blindings, commitments := apvssCompactRangeFixture(t, values, 8)
	proof, err := apvssProveCompactRange(statement, commitments, values, blindings, 8)
	if err != nil {
		t.Fatal(err)
	}
	one := fr.One()

	t.Run("polynomial response", func(t *testing.T) {
		bad := apvssCloneCompactRangeProofForTest(proof)
		bad.tHat.Add(&bad.tHat, &one)
		if err := apvssVerifyCompactRange(statement, commitments, bad, 8); err == nil {
			t.Fatal("accepted mutated compact range polynomial response")
		}
	})
	t.Run("inner product", func(t *testing.T) {
		bad := apvssCloneCompactRangeProofForTest(proof)
		bad.inner.a.Add(&bad.inner.a, &one)
		if err := apvssVerifyCompactRange(statement, commitments, bad, 8); err == nil {
			t.Fatal("accepted mutated compact range inner-product response")
		}
	})
	t.Run("statement", func(t *testing.T) {
		badStatement := append([]byte(nil), statement...)
		badStatement[0] ^= 1
		if err := apvssVerifyCompactRange(badStatement, commitments, proof, 8); err == nil {
			t.Fatal("accepted compact range proof under another statement")
		}
	})
	t.Run("commitment", func(t *testing.T) {
		badCommitments := append([]bls12381.G1Affine(nil), commitments...)
		badCommitments[0].Add(&badCommitments[0], &genG1)
		if err := apvssVerifyCompactRange(statement, badCommitments, proof, 8); err == nil {
			t.Fatal("accepted compact range proof for another commitment")
		}
	})
}

func TestAPVSSCompactRangeProofRejectsOutOfRangeWitnessV1(t *testing.T) {
	values := []uint64{256}
	statement, blindings, commitments := apvssCompactRangeFixture(t, values, 8)
	if _, err := apvssProveCompactRange(statement, commitments, values, blindings, 8); err == nil {
		t.Fatal("proved an 8-bit range for value 256")
	}
}
