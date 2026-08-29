package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCVV2ProductionKeyMaterialLoadsOnlyLocalSecrets(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	cfg.LocalNodeIDs = []int{cfg.OldCommittee[1]}
	cfg.CVLocalReceiverIDs = []int{cfg.NewCommittee[2]}
	cfg.CVPublicKeyDir = filepath.Join(t.TempDir(), "public")
	cfg.CVLocalSecretDir = filepath.Join(t.TempDir(), "secret")

	if err := GenerateCVV2KeyMaterial(cfg.CVPublicKeyDir, cfg.CVLocalSecretDir, cfg); err != nil {
		t.Fatal(err)
	}
	for _, member := range cfg.OldCommittee {
		if member == cfg.LocalNodeIDs[0] {
			continue
		}
		paths := []string{cvValidatorV2SecretPath(cfg.CVLocalSecretDir, member)}
		for _, role := range []string{cvV2RoleAPDB, cvV2RoleControl, cvV2RoleCoin} {
			paths = append(paths, cvV2ThresholdSecretPath(cfg.CVLocalSecretDir, role, member))
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, receiver := range cfg.NewCommittee {
		if receiver == cfg.CVLocalReceiverIDs[0] {
			continue
		}
		if err := os.Remove(cvReceiverV2EncryptionSecretPath(cfg.CVLocalSecretDir, receiver)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(cvReceiverV2IdentitySecretPath(cfg.CVLocalSecretDir, receiver)); err != nil {
			t.Fatal(err)
		}
	}

	runtime, err := cvLoadEpochRuntimeV2(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.validators.localSecrets) != 1 || len(runtime.receivers.localEncryptionSecrets) != 1 ||
		len(runtime.receivers.localIdentitySecrets) != 1 || len(runtime.apdbSigner.signingMembers) != 1 ||
		len(runtime.controlSigner.signingMembers) != 1 || len(runtime.coinSigner.signingMembers) != 1 {
		t.Fatal("CV V2 runtime loaded a non-local secret")
	}
	if runtime.context.SID != cfg.SID || runtime.context.Epoch != uint64(cfg.Epoch) ||
		len(runtime.context.ReceiverRegistryDigest) != 32 {
		t.Fatal("CV V2 runtime built the wrong public context")
	}
	if _, err := CVV2SetupBundleDigest(cfg.CVPublicKeyDir); err != nil {
		t.Fatal(err)
	}
}

func TestCVV2RuntimeRejectsWrongEpochAndLocalMultiplicity(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	cfg.LocalNodeIDs = []int{cfg.OldCommittee[0]}
	cfg.CVLocalReceiverIDs = []int{cfg.NewCommittee[0]}
	cfg.CVPublicKeyDir = filepath.Join(t.TempDir(), "public")
	cfg.CVLocalSecretDir = filepath.Join(t.TempDir(), "secret")
	if err := GenerateCVV2KeyMaterial(cfg.CVPublicKeyDir, cfg.CVLocalSecretDir, cfg); err != nil {
		t.Fatal(err)
	}

	wrongEpoch := cfg
	wrongEpoch.Epoch++
	if _, err := cvLoadEpochRuntimeV2(wrongEpoch); err == nil {
		t.Fatal("accepted epoch-bound CV V2 keys in another epoch")
	}
	multiple := cfg
	multiple.LocalNodeIDs = cfg.OldCommittee[:2]
	if _, err := cvLoadEpochRuntimeV2(multiple); err == nil {
		t.Fatal("accepted multiple local old members")
	}
}
