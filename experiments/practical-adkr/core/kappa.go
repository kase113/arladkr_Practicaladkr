package core

import (
	"fmt"
	"math"
	"strings"
)

type KappaProfile string

const (
	KappaProfilePracticalOriginal KappaProfile = "practical-original"
	KappaProfileMatchedSingle     KappaProfile = "matched-single-epoch"
	KappaProfileMatchedLifetime   KappaProfile = "matched-lifetime"
	KappaProfileHighAssurance     KappaProfile = "high-assurance"
	KappaProfileDeterministic     KappaProfile = "deterministic-inclusion"
	KappaProfileExplicit          KappaProfile = "explicit"
)

type KappaPolicy struct {
	Profile               KappaProfile
	PerEpochFailureTarget float64
	MatchedSecurityBits   float64
	LifetimeEpochs        uint64
}

const (
	defaultHighAssuranceBits   = 64
	defaultHighAssuranceEpochs = 525600
)

type KappaSelection struct {
	Kappa                     int
	Profile                   KappaProfile
	Population                int
	EpochFailureProbability   float64
	EpochFailureLog2          float64
	EpochSecurityBits         float64
	LifetimeEpochs            uint64
	LifetimeFailureUnionBound float64
	LifetimeFailureLog2       float64
	LifetimeSecurityBits      float64
	TargetEpochFailureLog2    float64
}

// ResolvePracticalKappa selects the smallest kappa satisfying the requested
// statistical failure budget for the minimal committee n=3f+1. It is kept for
// compatibility; callers that know n should use ResolvePracticalKappaForCommittee.
func ResolvePracticalKappa(f, explicit int, policy KappaPolicy) (KappaSelection, error) {
	return resolvePracticalKappa(3*f+1, f, explicit, policy)
}

// ResolvePracticalKappaForCommittee derives the effective fault threshold when
// f < 0 and validates the committee size before selecting kappa. Practical's
// sampling population remains |T|=2f+1; n determines the default maximum f
// and must satisfy the asynchronous Byzantine bound n >= 3f+1.
func ResolvePracticalKappaForCommittee(n, f, explicit int, policy KappaPolicy) (KappaSelection, error) {
	if n <= 0 {
		return KappaSelection{}, fmt.Errorf("invalid committee size n=%d", n)
	}
	if f < 0 {
		f = (n - 1) / 3
	}
	return resolvePracticalKappa(n, f, explicit, policy)
}

func resolvePracticalKappa(n, f, explicit int, policy KappaPolicy) (KappaSelection, error) {
	if f < 0 {
		return KappaSelection{}, fmt.Errorf("negative Byzantine threshold")
	}
	if n < 3*f+1 {
		return KappaSelection{}, fmt.Errorf("committee size n=%d does not satisfy n >= 3f+1 for f=%d", n, f)
	}
	population := 2*f + 1
	epochs := policy.LifetimeEpochs
	if explicit > 0 {
		if epochs == 0 {
			epochs = 1
		}
		if explicit > population {
			return KappaSelection{}, fmt.Errorf("explicit kappa=%d exceeds 2f+1=%d", explicit, population)
		}
		return practicalKappaSelection(f, explicit, KappaProfileExplicit, epochs, math.NaN()), nil
	}
	if explicit < 0 {
		return KappaSelection{}, fmt.Errorf("negative explicit kappa")
	}

	profile, err := normalizeKappaProfile(policy.Profile)
	if err != nil {
		return KappaSelection{}, err
	}
	if epochs == 0 {
		if profile == KappaProfileHighAssurance {
			epochs = defaultHighAssuranceEpochs
		} else {
			epochs = 1
		}
	}
	targetLog2 := 0.0
	switch profile {
	case KappaProfilePracticalOriginal:
		target := policy.PerEpochFailureTarget
		if target == 0 {
			target = 1e-10
		}
		if target <= 0 || target >= 1 || math.IsNaN(target) {
			return KappaSelection{}, fmt.Errorf("invalid Practical per-epoch failure target")
		}
		targetLog2 = math.Log2(target)
	case KappaProfileMatchedSingle:
		bits := policy.MatchedSecurityBits
		if bits == 0 {
			bits = 128
		}
		if bits <= 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
			return KappaSelection{}, fmt.Errorf("invalid matched security bits")
		}
		targetLog2 = -bits
	case KappaProfileMatchedLifetime:
		bits := policy.MatchedSecurityBits
		if bits == 0 {
			bits = 128
		}
		if bits <= 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
			return KappaSelection{}, fmt.Errorf("invalid matched security bits")
		}
		targetLog2 = -bits - math.Log2(float64(epochs))
	case KappaProfileHighAssurance:
		bits := policy.MatchedSecurityBits
		if bits == 0 {
			bits = defaultHighAssuranceBits
		}
		if bits <= 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
			return KappaSelection{}, fmt.Errorf("invalid high-assurance security bits")
		}
		targetLog2 = -bits - math.Log2(float64(epochs))
	case KappaProfileDeterministic:
		return practicalKappaSelection(f, f+1, profile, epochs, math.Inf(-1)), nil
	default:
		return KappaSelection{}, fmt.Errorf("unsupported kappa profile %q", profile)
	}

	for k := 1; k <= f+1; k++ {
		if PracticalKappaFailureLog2(f, k) <= targetLog2 {
			return practicalKappaSelection(f, k, profile, epochs, targetLog2), nil
		}
	}
	return KappaSelection{}, fmt.Errorf("no Practical kappa satisfies the requested failure budget")
}

func normalizeKappaProfile(profile KappaProfile) (KappaProfile, error) {
	switch strings.ToLower(strings.TrimSpace(string(profile))) {
	case "", "practical-original", "original", "paper":
		return KappaProfilePracticalOriginal, nil
	case "matched-single-epoch", "matched-single", "single-epoch":
		return KappaProfileMatchedSingle, nil
	case "matched-lifetime", "lifetime":
		return KappaProfileMatchedLifetime, nil
	case "high-assurance", "highassurance":
		return KappaProfileHighAssurance, nil
	case "deterministic-inclusion", "deterministic":
		return KappaProfileDeterministic, nil
	default:
		return "", fmt.Errorf("unknown kappa profile %q", profile)
	}
}

// PracticalKappaFailureLog2 returns log2(C(f,k)/C(2f+1,k)). A result of
// negative infinity denotes deterministic honest inclusion (k > f).
func PracticalKappaFailureLog2(f, k int) float64 {
	if f < 0 || k <= 0 || k > 2*f+1 {
		return math.NaN()
	}
	if k > f {
		return math.Inf(-1)
	}
	population := 2*f + 1
	log2Prob := 0.0
	for i := 0; i < k; i++ {
		log2Prob += math.Log2(float64(f-i)) - math.Log2(float64(population-i))
	}
	return log2Prob
}

func PracticalKappaFailureProbability(f, k int) float64 {
	return math.Exp2(PracticalKappaFailureLog2(f, k))
}

func practicalKappaSelection(
	f, k int,
	profile KappaProfile,
	epochs uint64,
	targetLog2 float64,
) KappaSelection {
	epochLog2 := PracticalKappaFailureLog2(f, k)
	lifetimeLog2 := epochLog2 + math.Log2(float64(epochs))
	lifetimeBound := math.Exp2(lifetimeLog2)
	if lifetimeBound > 1 {
		lifetimeBound = 1
		lifetimeLog2 = 0
	}
	return KappaSelection{
		Kappa:                     k,
		Profile:                   profile,
		Population:                2*f + 1,
		EpochFailureProbability:   math.Exp2(epochLog2),
		EpochFailureLog2:          epochLog2,
		EpochSecurityBits:         -epochLog2,
		LifetimeEpochs:            epochs,
		LifetimeFailureUnionBound: lifetimeBound,
		LifetimeFailureLog2:       lifetimeLog2,
		LifetimeSecurityBits:      -lifetimeLog2,
		TargetEpochFailureLog2:    targetLog2,
	}
}
