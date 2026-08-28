package core

import "testing"

func BenchmarkAPVSSFullExactLeafBaselineV1(b *testing.B) {
	context, leaves := cvBenchmarkFixture(b, 7, 2, 3)
	proofWire, err := cvLeafProofCanonicalBytes(leaves[0].proof)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cvVerifyLeaf(&context, leaves[0]); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(proofWire)), "proof_bytes")
}

func benchmarkAPVSSFallbackSetsV1(b *testing.B, run func(*testing.B, []int)) {
	b.Helper()
	for _, profile := range []struct {
		name     string
		fallback []int
	}{
		{name: "n7_f2_I_empty"},
		{name: "n7_f2_I_1", fallback: []int{1}},
		{name: "n7_f2_I_f", fallback: []int{1, 2}},
	} {
		b.Run(profile.name, func(b *testing.B) {
			run(b, profile.fallback)
		})
	}
}

func BenchmarkAPVSSPrototypeBuildV1(b *testing.B) {
	fixture := apvssFixture(b, 7, 2)
	benchmarkAPVSSFallbackSetsV1(b, func(b *testing.B, fallback []int) {
		prototype, err := apvssBuildPrototype(
			&fixture.context,
			fixture.leaf,
			fixture.receiverSecrets,
			fixture.signingSecrets,
			&fixture.witness,
			fallback,
		)
		if err != nil {
			b.Fatal(err)
		}
		proofBytes, err := apvssProofMaterialBytes(prototype)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := apvssBuildPrototype(
				&fixture.context,
				fixture.leaf,
				fixture.receiverSecrets,
				fixture.signingSecrets,
				&fixture.witness,
				fallback,
			); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(proofBytes), "proof_bytes")
	})
}

func BenchmarkAPVSSPrototypeVerifyV1(b *testing.B) {
	fixture := apvssFixture(b, 7, 2)
	benchmarkAPVSSFallbackSetsV1(b, func(b *testing.B, fallback []int) {
		prototype, err := apvssBuildPrototype(
			&fixture.context,
			fixture.leaf,
			fixture.receiverSecrets,
			fixture.signingSecrets,
			&fixture.witness,
			fallback,
		)
		if err != nil {
			b.Fatal(err)
		}
		proofBytes, err := apvssProofMaterialBytes(prototype)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := apvssVerifyPrototype(&fixture.context, prototype); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(proofBytes), "proof_bytes")
	})
}
