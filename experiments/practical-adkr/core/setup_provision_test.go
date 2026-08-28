package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPracticalSetupProvisionOwnerIsolationAndVerification(t *testing.T) {
	root := filepath.Join(t.TempDir(), "setup")
	cfg := Config{
		SID: "practical-adkr-bench", OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{4, 5, 6, 7}, F: 1, PaillierBits: 2048,
		MVBALocalNodeIDs: "0", ProtocolLocalNodeIDs: "0,4", StrictNetwork: true,
	}
	digest, err := GeneratePracticalSetupProvision(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("empty setup bundle digest")
	}

	for oldID := range cfg.OldCommittee {
		nodeDir := filepath.Join(root, "node-"+sixDigitID(oldID))
		entries, err := os.ReadDir(nodeDir)
		if err != nil {
			t.Fatal(err)
		}
		privateCount := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".private.json") {
				privateCount++
			}
		}
		if privateCount != 6 {
			t.Fatalf("node %d has %d private artifacts, want 6", oldID, privateCount)
		}
	}

	node0 := filepath.Join(root, "node-000000")
	gotDigest, err := VerifyPracticalSetupProvision(node0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != digest {
		t.Fatalf("bundle digest = %s, want %s", gotDigest, digest)
	}

	manifestRaw, err := os.ReadFile(filepath.Join(node0, "setup-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest practicalSetupManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(node0, manifest.PublicFiles[0].Name)
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, append(publicRaw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPracticalSetupProvision(node0, cfg); err == nil {
		t.Fatal("accepted mutated public artifact")
	}
	if err := os.WriteFile(publicPath, publicRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(node0, "foreign.private.json")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPracticalSetupProvision(node0, cfg); err == nil {
		t.Fatal("accepted non-local private artifact")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}

	privatePath := filepath.Join(node0, manifest.Nodes[0].PrivateFiles[0])
	missingPath := privatePath + ".missing"
	if err := os.Rename(privatePath, missingPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPracticalSetupProvision(node0, cfg); err == nil {
		t.Fatal("accepted missing owner-local private artifact")
	}
	if err := os.Rename(missingPath, privatePath); err != nil {
		t.Fatal(err)
	}
}

func TestPracticalReadOnlySetupDoesNotGenerate(t *testing.T) {
	t.Setenv("PRACTICAL_SETUP_READ_ONLY", "1")
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", t.TempDir())
	cfg := Config{
		SID: "practical-adkr-bench", OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{4, 5, 6, 7}, F: 1,
		ProtocolLocalNodeIDs: "0,4", StrictNetwork: true,
	}
	if _, err := loadPracticalSigningKeys(cfg, cfg.OldCommittee, cfg.NewCommittee); err == nil {
		t.Fatal("read-only setup generated missing signing artifacts")
	}
}

func sixDigitID(id int) string {
	return fmt.Sprintf("%06d", id)
}
