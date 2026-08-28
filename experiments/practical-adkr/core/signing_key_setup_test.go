package core

import (
	"bytes"
	"os"
	"testing"
)

func TestStrictSigningSetupRetainsOnlyLocalPrivateKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", dir)
	t.Setenv("RLADKR_RANDOM_SEED", "compromised-benchmark-seed-must-not-drive-strict-signing")
	oldCommittee := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	cfg := Config{
		StrictNetwork:        true,
		ProtocolLocalNodeIDs: "1,11",
	}
	keys, err := loadPracticalSigningKeys(cfg, oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.dealerECDSAPublic) != len(oldCommittee) || len(keys.oldEdPublic) != len(oldCommittee) || len(keys.recipientPublic) != len(newCommittee) {
		t.Fatalf("incomplete public key bundle: dealer=%d old_ed=%d recipient=%d",
			len(keys.dealerECDSAPublic), len(keys.oldEdPublic), len(keys.recipientPublic))
	}
	if len(keys.dealerECDSAPrivate) != 1 || keys.dealerECDSAPrivate[1] == nil {
		t.Fatalf("strict dealer private ownership=%v, want only node 1", mapKeysECDSA(keys.dealerECDSAPrivate))
	}
	if len(keys.oldEdPrivate) != 1 || len(keys.oldEdPrivate[1]) == 0 {
		t.Fatalf("strict old-node private ownership=%v, want only node 1", mapKeysEd25519(keys.oldEdPrivate))
	}
	if len(keys.recipientPrivate) != 1 || keys.recipientPrivate[11] == nil {
		t.Fatalf("strict recipient private ownership=%v, want only node 11", mapKeysECDSA(keys.recipientPrivate))
	}
	if keys.dealerECDSAPrivate[0] != nil || len(keys.oldEdPrivate[2]) != 0 || keys.recipientPrivate[12] != nil {
		t.Fatal("strict signing setup exposed a non-local private key")
	}
	deterministicDealer, err := setupECDSAKey(benchmarkSeed(), "practical-adkr:dealer-ecdsa", 0)
	if err != nil {
		t.Fatal(err)
	}
	if keys.dealerECDSAPublic[0].X.Cmp(deterministicDealer.X) == 0 && keys.dealerECDSAPublic[0].Y.Cmp(deterministicDealer.Y) == 0 {
		t.Fatal("strict signing public keys remain derivable from RLADKR_RANDOM_SEED")
	}
	publicPath := practicalSigningPublicPath(dir, oldCommittee, newCommittee)
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicRaw, []byte(`"private"`)) {
		t.Fatal("signing public artifact contains private material")
	}
	privateInfo, err := os.Stat(practicalSigningPrivatePath(publicPath, dealerECDSARole, 1))
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("signing private artifact mode=%o, want 600", privateInfo.Mode().Perm())
	}
	if _, err := readPracticalSigningPrivate(publicPath, dealerECDSARole, 0, make([]byte, 32)); err == nil {
		t.Fatal("private artifact accepted the wrong public digest")
	}

	secondCfg := cfg
	secondCfg.ProtocolLocalNodeIDs = "2,12"
	second, err := loadPracticalSigningKeys(secondCfg, oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.dealerECDSAPrivate) != 1 || second.dealerECDSAPrivate[2] == nil ||
		len(second.oldEdPrivate) != 1 || len(second.oldEdPrivate[2]) == 0 ||
		len(second.recipientPrivate) != 1 || second.recipientPrivate[12] == nil {
		t.Fatal("second strict process did not load exactly its local private keys")
	}
	if second.dealerECDSAPublic[0].X.Cmp(keys.dealerECDSAPublic[0].X) != 0 ||
		!bytes.Equal(second.oldEdPublic[0], keys.oldEdPublic[0]) ||
		second.recipientPublic[10].X.Cmp(keys.recipientPublic[10].X) != 0 {
		t.Fatal("strict processes loaded inconsistent public signing bundles")
	}
}

func TestLocalSigningSetupRetainsAllPrivateKeys(t *testing.T) {
	t.Setenv("RLADKR_RANDOM_SEED", "local-signing-ownership-test")
	oldCommittee := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	keys, err := loadPracticalSigningKeys(Config{}, oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.dealerECDSAPrivate) != len(oldCommittee) || len(keys.oldEdPrivate) != len(oldCommittee) || len(keys.recipientPrivate) != len(newCommittee) {
		t.Fatalf("local compatibility setup lost private keys: dealer=%d old_ed=%d recipient=%d",
			len(keys.dealerECDSAPrivate), len(keys.oldEdPrivate), len(keys.recipientPrivate))
	}
}

func mapKeysECDSA[V any](values map[int]V) []int {
	keys := make([]int, 0, len(values))
	for id := range values {
		keys = append(keys, id)
	}
	return keys
}

func mapKeysEd25519[V any](values map[int]V) []int {
	return mapKeysECDSA(values)
}
