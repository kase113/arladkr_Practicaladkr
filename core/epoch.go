package core

import "context"

func PrepareRuntime(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	_, err := cvLoadEpochRuntimeV2(cfg)
	return err
}

func PrepareConfigRuntime(cfg Config) (Config, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return cfg, err
	}
	runtime, err := cvLoadEpochRuntimeV2(cfg)
	if err != nil {
		return cfg, err
	}
	cfg.cvRuntimeV2 = runtime
	cfg.runtime = newRuntimeCommMetrics(cfg.CommMetrics)
	return cfg, nil
}

// RunEpoch has one production protocol path: scalar/group CV-sAPVSS V2 with
// direct aggregate-level Dumbo-MVBA.
func RunEpoch(ctx context.Context, cfg Config) (*EpochResult, error) {
	return RunCVEpochV2(ctx, NormalizeConfig(cfg))
}
