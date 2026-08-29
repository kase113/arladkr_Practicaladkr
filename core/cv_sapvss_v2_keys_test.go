package core

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCVReceiverRegistryV2GeneratesAndVerifiesIndependentKeys(t *testing.T) {
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	receivers := []int{10, 20, 30}
	if err := cvGenerateReceiverRegistryV2(publicDir, secretDir, "registry-v2", 7, receivers); err != nil {
		t.Fatalf("generate V2 receiver registry: %v", err)
	}
	material, err := cvLoadReceiverRegistryV2(publicDir, secretDir, "registry-v2", 7, receivers, []int{20})
	if err != nil {
		t.Fatalf("load V2 receiver registry: %v", err)
	}
	if len(material.registryDigest) != 32 || len(material.encryptionPublicKeys) != len(receivers) ||
		len(material.identityPublicKeys) != len(receivers) || material.receiverIndex[20] != 2 {
		t.Fatalf("invalid loaded V2 receiver material")
	}
	if _, ok := material.localEncryptionSecrets[20]; !ok {
		t.Fatal("local V2 encryption secret was not loaded")
	}
	if _, ok := material.localIdentitySecrets[20]; !ok {
		t.Fatal("local V2 identity secret was not loaded")
	}
	for _, path := range []string{
		cvReceiverV2EncryptionSecretPath(secretDir, 20),
		cvReceiverV2IdentitySecretPath(secretDir, 20),
	} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("V2 secret file permissions for %s = %v / %v", path, info, statErr)
		}
	}
}

func TestCVReceiverRegistryV2RejectsPoKAndEpochMutation(t *testing.T) {
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	receivers := []int{1, 2, 3}
	if err := cvGenerateReceiverRegistryV2(publicDir, secretDir, "registry-v2-mutation", 11, receivers); err != nil {
		t.Fatalf("generate V2 receiver registry: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(publicDir, cvReceiverRegistryV2Filename))
	if err != nil {
		t.Fatal(err)
	}
	var registry cvReceiverRegistryV2
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	proof, err := hex.DecodeString(registry.Receivers[0].EncryptionKeyProof)
	if err != nil || len(proof) == 0 {
		t.Fatal("generated proof is not valid hexadecimal")
	}
	proof[len(proof)-1] ^= 1
	registry.Receivers[0].EncryptionKeyProof = hex.EncodeToString(proof)
	mutated, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(publicDir, cvReceiverRegistryV2Filename), append(mutated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cvLoadReceiverRegistryV2(publicDir, secretDir, "registry-v2-mutation", 11, receivers, []int{1}); err == nil {
		t.Fatal("accepted a registry with a mutated encryption PoK")
	}
}

func TestCVReceiverRegistryV2RejectsWrongEpochBinding(t *testing.T) {
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	receivers := []int{1, 2, 3}
	if err := cvGenerateReceiverRegistryV2(publicDir, secretDir, "registry-v2-epoch", 3, receivers); err != nil {
		t.Fatalf("generate V2 receiver registry: %v", err)
	}
	if _, err := cvLoadReceiverRegistryV2(publicDir, secretDir, "registry-v2-epoch", 4, receivers, []int{1}); err == nil {
		t.Fatal("accepted V2 receiver registry under a different epoch")
	}
}
