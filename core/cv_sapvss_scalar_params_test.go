package core

import (
	"bytes"
	"math/big"
	"testing"
)

func cvScalarParamsTestConfig() Config {
	return Config{
		SID:                   "cv-v2-params",
		Epoch:                 1,
		OldCommittee:          []int{0, 1, 2, 3, 4, 5, 6},
		NewCommittee:          []int{10, 11, 12, 13},
		OldFaults:             2,
		NewFaults:             1,
		CVProposerSampleSize:  3,
		CVValidatorSampleSize: 3,
	}
}

func TestCVDeriveScalarParamsUsesExplicitFaultBounds(t *testing.T) {
	params, err := cvDeriveScalarParams(cvScalarParamsTestConfig())
	if err != nil {
		t.Fatalf("derive V2 params: %v", err)
	}
	if params.componentCount != 3 || params.poolSize != 5 ||
		params.apdbLockThreshold != 5 || params.decisionThreshold != 5 ||
		params.recoveryThreshold != 3 || params.newShareDegree != 2 ||
		params.newShareThreshold != 3 || params.validatorThreshold != 2 {
		t.Fatalf("unexpected V2 threshold derivation: %+v", params)
	}
	if params.proposerFailureBound.Sign() != 0 {
		t.Fatalf("proposer failure probability = %s, want 0", params.proposerFailureBound)
	}
	wantValidatorFailure := big.NewRat(1, 7)
	for name, got := range map[string]*big.Rat{
		"soundness": params.validatorSoundnessFailureBound,
		"liveness":  params.validatorLivenessFailureBound,
		"combined":  params.validatorCombinedFailureBound,
		"alias":     params.validatorFailureBound,
	} {
		if got.Cmp(wantValidatorFailure) != 0 {
			t.Fatalf("validator %s failure probability = %s, want %s", name, got, wantValidatorFailure)
		}
	}
}

func TestCVDeriveScalarParamsRejectsImplicitSamplesAndConflictingFaultBounds(t *testing.T) {
	missingSamples := cvScalarParamsTestConfig()
	missingSamples.CVProposerSampleSize = 0
	if _, err := cvDeriveScalarParams(missingSamples); err == nil {
		t.Fatal("accepted V2 parameters with an implicit proposer sample size")
	}
	evenValidators := cvScalarParamsTestConfig()
	evenValidators.CVValidatorSampleSize = 2
	if params, err := cvDeriveScalarParams(evenValidators); err != nil || params.validatorThreshold != 2 {
		t.Fatalf("rejected paper-compatible even validator sample: params=%+v err=%v", params, err)
	}

	conflict := cvScalarParamsTestConfig()
	conflict.FOld = 1
	if _, err := cvDeriveScalarParams(conflict); err == nil {
		t.Fatal("accepted conflicting legacy and V2 old fault bounds")
	}
}

func TestCVDeriveScalarParamsRejectsSampleSizesThatMislabelSecureTarget(t *testing.T) {
	cfg := Config{
		SID: "cv-v2-secure-target", Epoch: 1,
		OldCommittee: make([]int, 128), NewCommittee: []int{2000, 2001, 2002, 2003},
		OldFaults: 42, NewFaults: 1,
		CVProposerSampleSize: 3, CVValidatorSampleSize: 3,
		CVSamplingFailureTarget: "original",
	}
	for i := range cfg.OldCommittee {
		cfg.OldCommittee[i] = i
	}
	if _, err := cvDeriveScalarParams(cfg); err == nil {
		t.Fatal("accepted smoke sample sizes labeled with a 1e-8 failure target")
	}
	cfg.CVProposerSampleSize = 19
	cfg.CVValidatorSampleSize = 85
	if _, err := cvDeriveScalarParams(cfg); err != nil {
		t.Fatalf("rejected sample sizes resolved for the paper original profile: %v", err)
	}
}

func TestCVScalarStartupAcceptsAuditedAggregatedRangeBackend(t *testing.T) {
	if _, err := cvValidateScalarStartup(cvScalarParamsTestConfig()); err != nil {
		t.Fatalf("V2 startup rejected aggregated range backend: %v", err)
	}
}

func TestCVScalarProtocolVersionRejectsLegacyContextWire(t *testing.T) {
	if cvSAPVSSScalarProtocolVersion != "cv-sapvss-v2-scalar-group" {
		t.Fatalf("unexpected CV V2 protocol label %q", cvSAPVSSScalarProtocolVersion)
	}
	context := &cvLeafContextScalar{
		SID: "cv-v2-version", Epoch: 1, OldRoster: []int{0}, NewRoster: []int{1},
		ReceiverRegistryDigest: hashBytes([]byte("cv-v2-version-registry")),
		SharingDegree:          0,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: 1},
	}
	wire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		t.Fatal(err)
	}
	const legacyDomain = "ARL-CV-sAPVSS/v2/leaf-context"
	var legacy bytes.Buffer
	if err := cvWriteBytes(&legacy, []byte(legacyDomain)); err != nil {
		t.Fatal(err)
	}
	currentPrefixBytes := 4 + len(cvLeafContextWireDomainScalar)
	if len(wire) <= currentPrefixBytes {
		t.Fatal("invalid current CV V2 context wire")
	}
	legacy.Write(wire[currentPrefixBytes:])
	if _, err := cvDecodeLeafContextScalar(legacy.Bytes()); err == nil {
		t.Fatal("accepted legacy dual-lane CV V2 context wire")
	}
}

func TestCVScalarValidatorFailureBoundUsesExactIntegerArithmetic(t *testing.T) {
	soundness, liveness, combined, err := cvScalarValidatorFailureBounds(7, 2, 3, 2)
	if err != nil {
		t.Fatalf("compute validator failure bound: %v", err)
	}
	for name, got := range map[string]*big.Rat{"soundness": soundness, "liveness": liveness, "combined": combined} {
		if got.Cmp(big.NewRat(1, 7)) != 0 {
			t.Fatalf("validator %s failure probability = %s, want 1/7", name, got)
		}
	}
}

func TestCVScalarValidatorFailureBoundsExposeEvenSampleLivenessGap(t *testing.T) {
	soundness, liveness, combined, err := cvScalarValidatorFailureBounds(7, 2, 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	if soundness.Sign() != 0 || liveness.Cmp(big.NewRat(2, 7)) != 0 || combined.Cmp(liveness) != 0 {
		t.Fatalf("even-sample bounds soundness=%s liveness=%s combined=%s", soundness, liveness, combined)
	}
}

func TestCVScalarSecureSamplingOperatingPoints(t *testing.T) {
	targets := []struct {
		name                        string
		target                      *big.Rat
		wantProposer, wantValidator int
	}{
		{name: "1e-8", target: big.NewRat(1, 100000000), wantProposer: 15, wantValidator: 79},
		{name: "1e-10", target: big.NewRat(1, 10000000000), wantProposer: 18, wantValidator: 83},
	}
	for _, test := range targets {
		t.Run(test.name, func(t *testing.T) {
			proposer := 0
			for sample := 1; sample <= 128; sample++ {
				bound, err := cvScalarProposerFailureBound(128, 42, sample)
				if err != nil {
					t.Fatal(err)
				}
				if bound.Cmp(test.target) <= 0 {
					proposer = sample
					break
				}
			}
			validator := 0
			for sample := 1; sample <= 128; sample += 2 {
				threshold := (sample + 1) / 2
				_, _, bound, err := cvScalarValidatorFailureBounds(128, 42, sample, threshold)
				if err != nil {
					t.Fatal(err)
				}
				if bound.Cmp(test.target) <= 0 {
					validator = sample
					break
				}
			}
			if proposer != test.wantProposer || validator != test.wantValidator {
				t.Fatalf("minimum samples proposer=%d validator=%d, want %d/%d",
					proposer, validator, test.wantProposer, test.wantValidator)
			}
		})
	}
}
