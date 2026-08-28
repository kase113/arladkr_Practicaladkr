package core

import (
	"crypto/sha256"
	"math"
	"testing"
)

func TestResolvePracticalKappaMatchesPaperOperatingPoints(t *testing.T) {
	tests := []struct {
		name   string
		f      int
		target float64
		want   int
	}{
		{"n127-1e-8", 42, 1e-8, 22},
		{"n127-1e-10", 42, 1e-10, 26},
		{"n196-1e-8", 65, 1e-8, 23},
		{"n196-1e-10", 65, 1e-10, 28},
		{"n256-1e-8", 85, 1e-8, 24},
		{"n256-1e-10", 85, 1e-10, 29},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection, err := ResolvePracticalKappa(test.f, 0, KappaPolicy{
				Profile: KappaProfilePracticalOriginal, PerEpochFailureTarget: test.target,
			})
			if err != nil {
				t.Fatal(err)
			}
			if selection.Kappa != test.want {
				t.Fatalf("kappa=%d, want %d", selection.Kappa, test.want)
			}
		})
	}
}

func TestResolvePracticalKappaMatchedSecurityProfiles(t *testing.T) {
	tests := []struct {
		name    string
		f       int
		profile KappaProfile
		epochs  uint64
		want    int
	}{
		{"single-n128", 42, KappaProfileMatchedSingle, 1, 43},
		{"single-n196", 65, KappaProfileMatchedSingle, 1, 66},
		{"single-n256", 85, KappaProfileMatchedSingle, 1, 77},
		{"lifetime-n256", 85, KappaProfileMatchedLifetime, 525600, 82},
		{"lifetime-n512", 170, KappaProfileMatchedLifetime, 525600, 109},
		{"lifetime-n1024", 341, KappaProfileMatchedLifetime, 525600, 127},
		{"lifetime-n2048", 682, KappaProfileMatchedLifetime, 525600, 137},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection, err := ResolvePracticalKappa(test.f, 0, KappaPolicy{
				Profile: test.profile, MatchedSecurityBits: 128, LifetimeEpochs: test.epochs,
			})
			if err != nil {
				t.Fatal(err)
			}
			if selection.Kappa != test.want {
				t.Fatalf("kappa=%d, want %d", selection.Kappa, test.want)
			}
		})
	}
}

func TestResolvePracticalKappaDeterministicAndBounds(t *testing.T) {
	selection, err := ResolvePracticalKappa(10, 0, KappaPolicy{Profile: KappaProfileDeterministic})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Kappa != 11 || selection.EpochFailureProbability != 0 ||
		!math.IsInf(selection.EpochSecurityBits, 1) {
		t.Fatalf("unexpected deterministic selection: %+v", selection)
	}
	if _, err := ResolvePracticalKappa(10, 22, KappaPolicy{}); err == nil {
		t.Fatal("accepted explicit kappa above 2f+1")
	}
}

func TestResolvePracticalKappaDerivesFaultThresholdFromCommitteeSize(t *testing.T) {
	selection, err := ResolvePracticalKappaForCommittee(7, -1, 0, KappaPolicy{
		Profile:               KappaProfilePracticalOriginal,
		PerEpochFailureTarget: 1e-10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Kappa != 3 {
		t.Fatalf("n=7 should derive f=2 and kappa=3, got %d", selection.Kappa)
	}
	if _, err := ResolvePracticalKappaForCommittee(7, 3, 0, KappaPolicy{}); err == nil {
		t.Fatal("accepted n=7,f=3 despite n >= 3f+1 bound")
	}
}

func TestResolvePracticalKappaMatchesTenYear128BitTable(t *testing.T) {
	tests := []struct {
		n, want int
	}{
		{128, 43},
		{256, 82},
		{512, 109},
		{1024, 127},
		{2048, 137},
	}
	for _, test := range tests {
		selection, err := ResolvePracticalKappaForCommittee(test.n, -1, 0, KappaPolicy{
			Profile:             KappaProfileMatchedLifetime,
			MatchedSecurityBits: 128,
			LifetimeEpochs:      525600,
		})
		if err != nil {
			t.Fatalf("n=%d: %v", test.n, err)
		}
		if selection.Kappa != test.want {
			t.Fatalf("n=%d kappa=%d, want %d", test.n, selection.Kappa, test.want)
		}
	}
}

func TestResolvePracticalKappaHighAssuranceProfile(t *testing.T) {
	selection, err := ResolvePracticalKappaForCommittee(128, -1, 0, KappaPolicy{
		Profile: KappaProfileHighAssurance,
	})
	if err != nil {
		t.Fatal(err)
	}
	if selection.LifetimeEpochs != 525600 {
		t.Fatalf("high-assurance epochs=%d, want 525600", selection.LifetimeEpochs)
	}
	targetLog2 := -64 - math.Log2(float64(selection.LifetimeEpochs))
	if selection.EpochFailureLog2 > targetLog2 {
		t.Fatalf("high-assurance epoch log2=%g exceeds target %g", selection.EpochFailureLog2, targetLog2)
	}
	if selection.LifetimeSecurityBits < 64 {
		t.Fatalf("high-assurance lifetime security=%g, want at least 64 bits", selection.LifetimeSecurityBits)
	}
	alias, err := ResolvePracticalKappaForCommittee(128, -1, 0, KappaPolicy{Profile: "high-assurance"})
	if err != nil {
		t.Fatal(err)
	}
	if alias.Kappa != selection.Kappa || alias.LifetimeEpochs != selection.LifetimeEpochs {
		t.Fatalf("high-assurance alias=%+v differs from canonical profile=%+v", alias, selection)
	}
	compact, err := ResolvePracticalKappaForCommittee(128, -1, 0, KappaPolicy{Profile: "highassurance"})
	if err != nil {
		t.Fatal(err)
	}
	if compact.Kappa != selection.Kappa || compact.LifetimeEpochs != selection.LifetimeEpochs {
		t.Fatalf("highassurance alias=%+v differs from canonical profile=%+v", compact, selection)
	}
}

func TestCoinAndConfigRejectKappaClamping(t *testing.T) {
	digest := sha256.Sum256([]byte("coin input"))
	if _, err := selectByThresholdCoin([]int{0, 1, 2, 3, 4}, 6, []byte("signature"), digest[:]); err == nil {
		t.Fatal("coin selection silently clamped kappa above the decided set")
	}
	cfg := Config{
		SID:          "kappa-bounds",
		OldCommittee: []int{0, 1, 2, 3, 4, 5, 6},
		NewCommittee: []int{7, 8, 9, 10, 11, 12, 13},
		F:            2,
		Kappa:        6,
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("configuration accepted kappa above 2f+1")
	}
}
