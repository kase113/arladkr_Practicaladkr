package core

import "context"

func PrepareRuntime(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	_, err := cvLoadEpochRuntimeScalar(cfg)
	return err
}

func PrepareConfigRuntime(cfg Config) (Config, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return cfg, err
	}
	runtime, err := cvLoadEpochRuntimeScalar(cfg)
	if err != nil {
		return cfg, err
	}
	cfg.cvRuntimeScalar = runtime
	cfg.runtime = newRuntimeCommMetrics(cfg.CommMetrics)
	return cfg, nil
}

// RunEpoch executes the production scalar CV-sAPVSS protocol.
func RunEpoch(ctx context.Context, cfg Config) (*EpochResult, error) {
	return RunCVEpochScalar(ctx, NormalizeConfig(cfg))
}
