package core

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type CVV2SamplingReport struct {
	Target                string `json:"target"`
	Profile               string `json:"profile"`
	Policy                string `json:"policy"`
	FaultFraction         string `json:"fault_fraction"`
	TotalFailureBudget    string `json:"total_failure_budget,omitempty"`
	PerEventFailureTarget string `json:"per_event_failure_target,omitempty"`
	// Kept for compatibility with older manifests. Exact finite-population
	// profiles report FaultFraction instead.
	WorstCaseByzantineFraction           string `json:"worst_case_byzantine_fraction,omitempty"`
	ProposerSampleSize                   int    `json:"proposer_sample_size"`
	ValidatorSampleSize                  int    `json:"validator_sample_size"`
	ValidatorThreshold                   int    `json:"validator_threshold"`
	ProposerFailureBound                 string `json:"proposer_failure_bound"`
	ValidatorSoundnessFailureBound       string `json:"validator_soundness_failure_bound"`
	ValidatorLivenessFailureBound        string `json:"validator_liveness_failure_bound"`
	ValidatorCombinedFailureBound        string `json:"validator_combined_failure_bound"`
	ContributorSamplingFailureBound      string `json:"contributor_sampling_failure_bound"`
	PerEpochCombinedSamplingFailureBound string `json:"per_epoch_combined_sampling_failure_bound"`
}

func ResolveCVV2Sampling(
	n, f int, target string, smokeProposerSample, smokeValidatorSample int,
) (CVV2SamplingReport, error) {
	if n <= 0 || f < 0 || f >= n {
		return CVV2SamplingReport{}, fmt.Errorf("invalid CV V2 sampling committee")
	}
	normalized := strings.ToLower(strings.TrimSpace(target))
	if normalized == "" {
		normalized = "smoke"
	}
	proposerSample := smokeProposerSample
	validatorSample := smokeValidatorSample
	policy := "explicit-smoke"
	profile := "smoke"
	var totalBudget *big.Rat
	var perEventTarget *big.Rat
	var err error
	if normalized != "smoke" {
		normalized, profile, totalBudget, err = cvResolveFailureBudgetV2(normalized)
		if err != nil {
			return CVV2SamplingReport{}, err
		}
		if n < 3*f+1 {
			return CVV2SamplingReport{}, fmt.Errorf("CV V2 secure sampling requires n >= 3f+1")
		}
		perEventTarget = new(big.Rat).Quo(new(big.Rat).Set(totalBudget), big.NewRat(2, 1))
		proposerSample, validatorSample, err = cvV2ExactFinitePopulationSampleSizes(n, f, perEventTarget)
		if err != nil {
			return CVV2SamplingReport{}, err
		}
		policy = "exact-finite-population"
	}
	if proposerSample <= 0 || proposerSample > n || validatorSample <= 0 ||
		validatorSample > n {
		return CVV2SamplingReport{}, fmt.Errorf("invalid CV V2 smoke sampling parameters")
	}
	threshold := validatorSample/2 + 1
	proposer, err := cvV2ProposerFailureBound(n, f, proposerSample)
	if err != nil {
		return CVV2SamplingReport{}, err
	}
	soundness, liveness, combined, err := cvV2ValidatorFailureBounds(n, f, validatorSample, threshold)
	if err != nil {
		return CVV2SamplingReport{}, err
	}
	if perEventTarget != nil && (proposer.Cmp(perEventTarget) > 0 || combined.Cmp(perEventTarget) > 0) {
		return CVV2SamplingReport{}, fmt.Errorf(
			"CV V2 exact samples do not meet per-event target for %s at n=%d f=%d", normalized, n, f,
		)
	}
	perEpoch := new(big.Rat).Add(proposer, combined)
	if totalBudget != nil && perEpoch.Cmp(totalBudget) > 0 {
		return CVV2SamplingReport{}, fmt.Errorf("CV V2 combined sampling bound exceeds total budget %s", normalized)
	}
	totalBudgetText := ""
	perEventTargetText := ""
	if totalBudget != nil {
		totalBudgetText = totalBudget.RatString()
		perEventTargetText = perEventTarget.RatString()
	}
	return CVV2SamplingReport{
		Target: normalized, Profile: profile, Policy: policy, FaultFraction: fmt.Sprintf("%d/%d", f, n),
		TotalFailureBudget: totalBudgetText, PerEventFailureTarget: perEventTargetText,
		ProposerSampleSize: proposerSample, ValidatorSampleSize: validatorSample,
		ValidatorThreshold: threshold, ProposerFailureBound: proposer.RatString(),
		ValidatorSoundnessFailureBound:       soundness.RatString(),
		ValidatorLivenessFailureBound:        liveness.RatString(),
		ValidatorCombinedFailureBound:        combined.RatString(),
		ContributorSamplingFailureBound:      "0",
		PerEpochCombinedSamplingFailureBound: perEpoch.RatString(),
	}, nil
}

func cvV2ExactFinitePopulationSampleSizes(n, f int, perEventTarget *big.Rat) (int, int, error) {
	if n <= 0 || f < 0 || f >= n || perEventTarget == nil || perEventTarget.Sign() <= 0 ||
		perEventTarget.Cmp(big.NewRat(1, 1)) >= 0 {
		return 0, 0, fmt.Errorf("invalid CV V2 exact sampling target")
	}
	proposerSample := 0
	for sample := 1; sample <= n; sample++ {
		bound, err := cvV2ProposerFailureBound(n, f, sample)
		if err != nil {
			return 0, 0, err
		}
		if bound.Cmp(perEventTarget) <= 0 {
			proposerSample = sample
			break
		}
	}
	validatorSample := 0
	for sample := 1; sample <= n; sample++ {
		threshold := sample/2 + 1
		_, _, combined, err := cvV2ValidatorFailureBounds(n, f, sample, threshold)
		if err != nil {
			return 0, 0, err
		}
		if combined.Cmp(perEventTarget) <= 0 {
			validatorSample = sample
			break
		}
	}
	if proposerSample == 0 || validatorSample == 0 {
		return 0, 0, fmt.Errorf("CV V2 sampling target is unattainable for n=%d f=%d", n, f)
	}
	return proposerSample, validatorSample, nil
}

func CVV2SamplingUnionBound(report CVV2SamplingReport, epochs int) (string, error) {
	if epochs < 0 {
		return "", fmt.Errorf("CV V2 sampling epoch count must be non-negative")
	}
	perEpoch, ok := new(big.Rat).SetString(report.PerEpochCombinedSamplingFailureBound)
	if !ok || perEpoch.Sign() < 0 {
		return "", fmt.Errorf("invalid CV V2 per-epoch sampling failure bound")
	}
	bound := new(big.Rat).Mul(perEpoch, new(big.Rat).SetInt64(int64(epochs)))
	if bound.Cmp(big.NewRat(1, 1)) > 0 {
		bound.SetInt64(1)
	}
	return bound.RatString(), nil
}

func cvParseFailureTargetV2(value string) (*big.Rat, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "2^-") {
		exponent, err := strconv.Atoi(strings.TrimPrefix(value, "2^-"))
		if err != nil || exponent <= 0 {
			return nil, fmt.Errorf("invalid CV V2 failure target %q", value)
		}
		return new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), uint(exponent))), nil
	}
	parts := strings.Split(value, "e-")
	if len(parts) == 2 {
		coefficient, ok := new(big.Int).SetString(parts[0], 10)
		exponent, err := strconv.Atoi(parts[1])
		if !ok || err != nil || coefficient.Sign() <= 0 || exponent <= 0 {
			return nil, fmt.Errorf("invalid CV V2 failure target %q", value)
		}
		denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
		target := new(big.Rat).SetFrac(coefficient, denominator)
		if target.Cmp(big.NewRat(1, 1)) >= 0 {
			return nil, fmt.Errorf("CV V2 failure target must be below one")
		}
		return target, nil
	}
	return nil, fmt.Errorf("unsupported CV V2 failure target %q", value)
}

func cvResolveFailureBudgetV2(value string) (target, profile string, budget *big.Rat, err error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "original":
		return value, value, big.NewRat(1, 10_000_000_000), nil
	case "high-assurance":
		denominator := new(big.Int).Lsh(big.NewInt(1), 64)
		denominator.Mul(denominator, big.NewInt(525_600))
		return value, value, new(big.Rat).SetFrac(big.NewInt(1), denominator), nil
	default:
		parsed, parseErr := cvParseFailureTargetV2(value)
		if parseErr != nil {
			return "", "", nil, parseErr
		}
		return value, "custom", parsed, nil
	}
}
