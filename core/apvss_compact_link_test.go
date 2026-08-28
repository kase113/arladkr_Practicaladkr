package core

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func apvssCloneCompactLinkProofForTest(in *apvssCompactLinkProof) *apvssCompactLinkProof {
	if in == nil {
		return nil
	}
	out := &apvssCompactLinkProof{lanes: make([]apvssCompactLinkLaneProof, len(in.lanes))}
	for laneIndex := range in.lanes {
		out.lanes[laneIndex] = in.lanes[laneIndex]
		out.lanes[laneIndex].digits = append(
			[]apvssCompactLinkDigitProof(nil),
			in.lanes[laneIndex].digits...,
		)
	}
	return out
}

func TestAPVSSCompactLinkProofV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	proof, err := apvssProveCompactLink(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyCompactLink(fixture.leaf, proof); err != nil {
		t.Fatalf("valid APVSS compact-link proof rejected: %v", err)
	}
	linkBytes, err := apvssCompactLinkProofBytes(fixture.leaf, proof)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := apvssBuildPrototype(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		fixture.signingSecrets,
		&fixture.witness,
		[]int{1, 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	exactBytes, err := apvssProofMaterialBytes(exact)
	if err != nil {
		t.Fatal(err)
	}
	if linkBytes >= exactBytes {
		t.Fatalf("compact-link bytes = %d, exact fallback material = %d", linkBytes, exactBytes)
	}
	if err := apvssRequireFallbackBackend(apvssFallbackCompactBatchProfile); err != nil {
		t.Fatalf("completed experimental compact backend is unavailable: %v", err)
	}
	if err := apvssRequireProductionFallbackBackend(apvssFallbackCompactBatchProfile); err == nil {
		t.Fatal("experimental compact backend crossed the production admission gate")
	}
}

func TestAPVSSCompactLinkProofRejectsMutationV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	proof, err := apvssProveCompactLink(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	one := fr.One()

	t.Run("digit response", func(t *testing.T) {
		bad := apvssCloneCompactLinkProofForTest(proof)
		bad.lanes[0].digits[0].zDigit.Add(&bad.lanes[0].digits[0].zDigit, &one)
		if err := apvssVerifyCompactLink(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated compact-link digit response")
		}
	})
	t.Run("digit commitment", func(t *testing.T) {
		bad := apvssCloneCompactLinkProofForTest(proof)
		bad.lanes[0].digits[0].commitment.Add(
			&bad.lanes[0].digits[0].commitment,
			&genG1,
		)
		if err := apvssVerifyCompactLink(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated compact-link digit commitment")
		}
	})
	t.Run("complete ciphertext", func(t *testing.T) {
		badLeaf := cvCloneLeafForTest(fixture.leaf)
		badLeaf.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&badLeaf.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		if err := apvssVerifyCompactLink(badLeaf, proof); err == nil {
			t.Fatal("accepted compact-link proof for a replaced ciphertext")
		}
	})
	t.Run("ordered I", func(t *testing.T) {
		bad := apvssCloneCompactLinkProofForTest(proof)
		bad.lanes[0], bad.lanes[1] = bad.lanes[1], bad.lanes[0]
		if err := apvssVerifyCompactLink(fixture.leaf, bad); err == nil {
			t.Fatal("accepted reordered compact-link I")
		}
	})
	t.Run("Pedersen evaluation", func(t *testing.T) {
		badLeaf := cvCloneLeafForTest(fixture.leaf)
		badLeaf.receivers[0].encryptedShare.commitment.Add(
			&badLeaf.receivers[0].encryptedShare.commitment,
			&genG1,
		)
		if err := apvssVerifyCompactLink(badLeaf, proof); err == nil {
			t.Fatal("accepted compact-link proof for a replaced Pedersen evaluation")
		}
	})
	t.Run("blinding ciphertext", func(t *testing.T) {
		badLeaf := cvCloneLeafForTest(fixture.leaf)
		badLeaf.receivers[0].encryptedShare.blinding.c.Add(
			&badLeaf.receivers[0].encryptedShare.blinding.c,
			&genG1,
		)
		if err := apvssVerifyCompactLink(badLeaf, proof); err == nil {
			t.Fatal("accepted compact-link proof for a replaced blinding ciphertext")
		}
	})
}

func BenchmarkAPVSSCompactLinkProveN7F2V1(b *testing.B) {
	fixture := apvssFixture(b, 7, 2)
	proof, err := apvssProveCompactLink(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		b.Fatal(err)
	}
	proofBytes, err := apvssCompactLinkProofBytes(fixture.leaf, proof)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := apvssProveCompactLink(fixture.leaf, &fixture.witness, []int{1, 2}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(proofBytes), "link_proof_bytes")
}

func BenchmarkAPVSSCompactLinkVerifyN7F2V1(b *testing.B) {
	fixture := apvssFixture(b, 7, 2)
	proof, err := apvssProveCompactLink(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		b.Fatal(err)
	}
	proofBytes, err := apvssCompactLinkProofBytes(fixture.leaf, proof)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := apvssVerifyCompactLink(fixture.leaf, proof); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(proofBytes), "link_proof_bytes")
}
