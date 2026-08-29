package core

import (
	"fmt"
	"math/big"
)

const cvSAPVSSScalarProtocolVersion = "cv-sapvss-v2-scalar-group"

// cvScalarParams is the single source of derived scalar CV thresholds. New protocol
// code must use this structure instead of reading the legacy FOld/FNew fields.
type cvScalarParams struct {
	oldFaults int
	newFaults int

	componentCount      int
	poolSize            int
	apdbLockThreshold   int
	decisionThreshold   int
	recoveryThreshold   int
	newShareDegree      int
	newShareThreshold   int
	proposerSampleSize  int
	validatorSampleSize int
	validatorThreshold  int

	proposerFailureBound           *big.Rat
	validatorSoundnessFailureBound *big.Rat
	validatorLivenessFailureBound  *big.Rat
	validatorCombinedFailureBound  *big.Rat
	validatorFailureBound          *big.Rat // compatibility alias for the combined bound
}

func cvDeriveScalarParams(cfg Config) (cvScalarParams, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return cvScalarParams{}, err
	}
	if c.CVProposerSampleSize <= 0 || c.CVProposerSampleSize > len(c.OldCommittee) {
		return cvScalarParams{}, fmt.Errorf("CV V2 proposer sample size must be in [1,n_o]")
	}
	if c.CVValidatorSampleSize <= 0 || c.CVValidatorSampleSize > len(c.OldCommittee) {
		return cvScalarParams{}, fmt.Errorf("CV V2 validator sample size must be in [1,n_o]")
	}
	sampling, err := ResolveCVScalarSampling(
		len(c.OldCommittee), c.OldFaults, c.CVSamplingFailureTarget,
		c.CVProposerSampleSize, c.CVValidatorSampleSize,
	)
	if err != nil {
		return cvScalarParams{}, err
	}
	if sampling.ProposerSampleSize != c.CVProposerSampleSize ||
		sampling.ValidatorSampleSize != c.CVValidatorSampleSize {
		return cvScalarParams{}, fmt.Errorf(
			"CV V2 sample sizes do not match failure target %s: got (%d,%d), want (%d,%d)",
			sampling.Target, c.CVProposerSampleSize, c.CVValidatorSampleSize,
			sampling.ProposerSampleSize, sampling.ValidatorSampleSize,
		)
	}

	oldCount := len(c.OldCommittee)
	newCount := len(c.NewCommittee)
	componentCount := c.OldFaults + 1
	poolSize := oldCount - c.OldFaults
	validatorThreshold := c.CVValidatorSampleSize/2 + 1
	if validatorThreshold > poolSize {
		return cvScalarParams{}, fmt.Errorf("CV V2 validator threshold exceeds honest old-committee capacity")
	}
	if 2*c.OldFaults+1 > oldCount {
		return cvScalarParams{}, fmt.Errorf("CV V2 APDB lock threshold exceeds old committee")
	}
	if componentCount > poolSize || poolSize > oldCount {
		return cvScalarParams{}, fmt.Errorf("invalid CV V2 component/pool thresholds")
	}
	if newCount-c.NewFaults <= 0 {
		return cvScalarParams{}, fmt.Errorf("invalid CV V2 new-committee threshold")
	}

	// scalar CV fixes the concrete scalar encoding to B=2^8. cvProfile checks
	// U=K(B-1)<q and the implementation's bounded-DLog capacity.
	if _, _, _, err := cvProfile(cvChunkProfile{chunkBits: 8, maxComponents: componentCount}); err != nil {
		return cvScalarParams{}, fmt.Errorf("invalid CV V2 scalar bounds: %w", err)
	}
	proposerFailure, err := cvScalarProposerFailureBound(oldCount, c.OldFaults, c.CVProposerSampleSize)
	if err != nil {
		return cvScalarParams{}, err
	}
	validatorSoundnessFailure, validatorLivenessFailure, validatorCombinedFailure, err := cvScalarValidatorFailureBounds(
		oldCount, c.OldFaults, c.CVValidatorSampleSize, validatorThreshold,
	)
	if err != nil {
		return cvScalarParams{}, err
	}

	return cvScalarParams{
		oldFaults:                      c.OldFaults,
		newFaults:                      c.NewFaults,
		componentCount:                 componentCount,
		poolSize:                       poolSize,
		apdbLockThreshold:              2*c.OldFaults + 1,
		decisionThreshold:              poolSize,
		recoveryThreshold:              componentCount,
		newShareDegree:                 newCount - c.NewFaults - 1,
		newShareThreshold:              newCount - c.NewFaults,
		proposerSampleSize:             c.CVProposerSampleSize,
		validatorSampleSize:            c.CVValidatorSampleSize,
		validatorThreshold:             validatorThreshold,
		proposerFailureBound:           proposerFailure,
		validatorSoundnessFailureBound: validatorSoundnessFailure,
		validatorLivenessFailureBound:  validatorLivenessFailure,
		validatorCombinedFailureBound:  validatorCombinedFailure,
		validatorFailureBound:          validatorCombinedFailure,
	}, nil
}

func cvScalarProposerFailureBound(n, f, sampleSize int) (*big.Rat, error) {
	if n <= 0 || f < 0 || f >= n || sampleSize <= 0 || sampleSize > n {
		return nil, fmt.Errorf("invalid CV V2 proposer sampling parameters")
	}
	return new(big.Rat).SetFrac(binomial(f, sampleSize), binomial(n, sampleSize)), nil
}

func cvScalarValidatorFailureBounds(
	n, f, sampleSize, threshold int,
) (soundness, liveness, combined *big.Rat, err error) {
	if n <= 0 || f < 0 || f >= n || sampleSize <= 0 || sampleSize > n ||
		threshold <= 0 || threshold > sampleSize {
		return nil, nil, nil, fmt.Errorf("invalid CV V2 validator sampling parameters")
	}
	soundness, err = cvScalarHypergeometricFaultTail(n, f, sampleSize, threshold)
	if err != nil {
		return nil, nil, nil, err
	}
	livenessThreshold := sampleSize - threshold + 1
	liveness, err = cvScalarHypergeometricFaultTail(n, f, sampleSize, livenessThreshold)
	if err != nil {
		return nil, nil, nil, err
	}
	combinedThreshold := threshold
	if livenessThreshold < combinedThreshold {
		combinedThreshold = livenessThreshold
	}
	combined, err = cvScalarHypergeometricFaultTail(n, f, sampleSize, combinedThreshold)
	return soundness, liveness, combined, err
}

func cvScalarHypergeometricFaultTail(n, f, sampleSize, minimumFaulty int) (*big.Rat, error) {
	if n <= 0 || f < 0 || f >= n || sampleSize <= 0 || sampleSize > n ||
		minimumFaulty <= 0 || minimumFaulty > sampleSize {
		return nil, fmt.Errorf("invalid CV V2 hypergeometric tail parameters")
	}
	numerator := new(big.Int)
	upper := f
	if sampleSize < upper {
		upper = sampleSize
	}
	for faulty := minimumFaulty; faulty <= upper; faulty++ {
		term := new(big.Int).Mul(binomial(f, faulty), binomial(n-f, sampleSize-faulty))
		numerator.Add(numerator, term)
	}
	return new(big.Rat).SetFrac(numerator, binomial(n, sampleSize)), nil
}

// cvRequireScalarFallbackBackend is deliberately separate from legacy admission.
// scalar protocol uses the audited, domain-separated aggregated Bulletproof adapter and its
// exact fallback-link commitments.
func cvRequireScalarFallbackBackend() error {
	return nil
}

func cvValidateScalarStartup(cfg Config) (cvScalarParams, error) {
	params, err := cvDeriveScalarParams(cfg)
	if err != nil {
		return cvScalarParams{}, err
	}
	if err := cvRequireScalarFallbackBackend(); err != nil {
		return cvScalarParams{}, err
	}
	return params, nil
}
