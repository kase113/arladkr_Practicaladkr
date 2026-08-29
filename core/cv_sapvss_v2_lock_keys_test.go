package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCVOldCommitteeKeyBundleV2UsesIndependentRoleKeys(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatalf("generate V2 key bundle: %v", err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatalf("load V2 key bundle: %v", err)
	}
	if bundle.apdb.threshold != 5 || bundle.control.threshold != 5 || bundle.coin.threshold != 3 {
		t.Fatalf("unexpected V2 role thresholds: APDB=%d control=%d coin=%d", bundle.apdb.threshold, bundle.control.threshold, bundle.coin.threshold)
	}
	apdbBytes := bundle.apdb.groupPublic.Bytes()
	controlBytes := bundle.control.groupPublic.Bytes()
	coinBytes := bundle.coin.groupPublic.Bytes()
	if bytes.Equal(apdbBytes[:], controlBytes[:]) || bytes.Equal(apdbBytes[:], coinBytes[:]) || bytes.Equal(controlBytes[:], coinBytes[:]) {
		t.Fatal("V2 key bundle reused a group public key across roles")
	}
	for _, role := range []string{cvV2RoleAPDB, cvV2RoleControl, cvV2RoleCoin} {
		info, statErr := os.Stat(cvV2ThresholdSecretPath(secretDir, role, 0))
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("V2 role secret permissions for %s = %v / %v", role, info, statErr)
		}
	}
	signer, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatalf("build V2 APDB signer: %v", err)
	}
	digest := hashBytes([]byte("V2 key bundle signer test"))
	shares := make(map[int][]byte, bundle.apdb.threshold)
	for _, member := range cfg.OldCommittee[:bundle.apdb.threshold] {
		share, signErr := signer.SignShare(member, "CV_V2_APDB_TEST", digest)
		if signErr != nil || !signer.VerifyShare(member, "CV_V2_APDB_TEST", digest, share) {
			t.Fatalf("invalid V2 APDB share for member %d: %v", member, signErr)
		}
		shares[member] = share
	}
	recovered, err := signer.Recover("CV_V2_APDB_TEST", digest, shares)
	if err != nil || !signer.VerifyRecovered("CV_V2_APDB_TEST", digest, recovered) {
		t.Fatalf("recover V2 APDB certificate: %v", err)
	}
}

func TestCVOldCommitteeKeyBundleV2RejectsRoleMutation(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(publicDir, cvOldCommitteeKeyBundleV2Filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var registry cvOldCommitteeKeyBundleV2Registry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	registry.Roles[0].Threshold--
	mutated, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(mutated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, []int{0}, params); err == nil {
		t.Fatal("accepted V2 role threshold mutation")
	}
}
