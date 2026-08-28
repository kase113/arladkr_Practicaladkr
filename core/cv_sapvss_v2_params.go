package core

import (
	"fmt"
	"math/big"
)

const cvSAPVSSV2ProtocolVersion = "cv-sapvss-v2-scalar-group"

// cvV2Params is the single source of derived CV V2 thresholds. New protocol
// code must use this structure instead of reading the legacy FOld/FNew fields.
type cvV2Params struct {
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

func cvDeriveV2Params(cfg Config) (cvV2Params, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return cvV2Params{}, err
	}
	if c.CVProposerSampleSize <= 0 || c.CVProposerSampleSize > len(c.OldCommittee) {
		return cvV2Params{}, fmt.Errorf("CV V2 proposer sample size must be in [1,n_o]")
	}
	if c.CVValidatorSampleSize <= 0 || c.CVValidatorSampleSize > len(c.OldCommittee) {
		return cvV2Params{}, fmt.Errorf("CV V2 validator sample size must be in [1,n_o]")
	}
	sampling, err := ResolveCVV2Sampling(
		len(c.OldCommittee), c.OldFaults, c.CVSamplingFailureTarget,
		c.CVProposerSampleSize, c.CVValidatorSampleSize,
	)
	if err != nil {
		return cvV2Params{}, err
	}
	if sampling.ProposerSampleSize != c.CVProposerSampleSize ||
		sampling.ValidatorSampleSize != c.CVValidatorSampleSize {
		return cvV2Params{}, fmt.Errorf(
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
		return cvV2Params{}, fmt.Errorf("CV V2 validator threshold exceeds honest old-committee capacity")
	}
	if 2*c.OldFaults+1 > oldCount {
		return cvV2Params{}, fmt.Errorf("CV V2 APDB lock threshold exceeds old committee")
	}
	if componentCount > poolSize || poolSize > oldCount {
		return cvV2Params{}, fmt.Errorf("invalid CV V2 component/pool thresholds")
	}
	if newCount-c.NewFaults <= 0 {
		return cvV2Params{}, fmt.Errorf("invalid CV V2 new-committee threshold")
	}

	// CV V2 fixes the concrete scalar encoding to B=2^8. cvProfile checks
	// U=K(B-1)<q and the implementation's bounded-DLog capacity.
	if _, _, _, err := cvProfile(cvChunkProfile{chunkBits: 8, maxComponents: componentCount}); err != nil {
		return cvV2Params{}, fmt.Errorf("invalid CV V2 scalar bounds: %w", err)
	}
	proposerFailure, err := cvV2ProposerFailureBound(oldCount, c.OldFaults, c.CVProposerSampleSize)
	if err != nil {
		return cvV2Params{}, err
	}
	validatorSoundnessFailure, validatorLivenessFailure, validatorCombinedFailure, err := cvV2ValidatorFailureBounds(
		oldCount, c.OldFaults, c.CVValidatorSampleSize, validatorThreshold,
	)
	if err != nil {
		return cvV2Params{}, err
	}

	return cvV2Params{
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

func cvV2ProposerFailureBound(n, f, sampleSize int) (*big.Rat, error) {
	if n <= 0 || f < 0 || f >= n || sampleSize <= 0 || sampleSize > n {
		return nil, fmt.Errorf("invalid CV V2 proposer sampling parameters")
	}
	return new(big.Rat).SetFrac(binomial(f, sampleSize), binomial(n, sampleSize)), nil
}

func cvV2ValidatorFailureBound(n, f, sampleSize, threshold int) (*big.Rat, error) {
	_, _, combined, err := cvV2ValidatorFailureBounds(n, f, sampleSize, threshold)
	return combined, err
}

func cvV2ValidatorFailureBounds(
	n, f, sampleSize, threshold int,
) (soundness, liveness, combined *big.Rat, err error) {
	if n <= 0 || f < 0 || f >= n || sampleSize <= 0 || sampleSize > n ||
		threshold <= 0 || threshold > sampleSize {
		return nil, nil, nil, fmt.Errorf("invalid CV V2 validator sampling parameters")
	}
	soundness, err = cvV2HypergeometricFaultTail(n, f, sampleSize, threshold)
	if err != nil {
		return nil, nil, nil, err
	}
	livenessThreshold := sampleSize - threshold + 1
	liveness, err = cvV2HypergeometricFaultTail(n, f, sampleSize, livenessThreshold)
	if err != nil {
		return nil, nil, nil, err
	}
	combinedThreshold := threshold
	if livenessThreshold < combinedThreshold {
		combinedThreshold = livenessThreshold
	}
	combined, err = cvV2HypergeometricFaultTail(n, f, sampleSize, combinedThreshold)
	return soundness, liveness, combined, err
}

func cvV2HypergeometricFaultTail(n, f, sampleSize, minimumFaulty int) (*big.Rat, error) {
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

// cvRequireV2FallbackBackend is deliberately separate from legacy admission.
// V2 uses the audited, domain-separated aggregated Bulletproof adapter and its
// exact fallback-link commitments.
func cvRequireV2FallbackBackend() error {
	return nil
}

func cvValidateV2Startup(cfg Config) (cvV2Params, error) {
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		return cvV2Params{}, err
	}
	if err := cvRequireV2FallbackBackend(); err != nil {
		return cvV2Params{}, err
	}
	return params, nil
}
