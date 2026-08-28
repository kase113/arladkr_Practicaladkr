package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVReceiverKeyMaterialGenerateAndLoadLocalOnly(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	const sid = "cv-keys-session"
	receiverIDs := []int{10, 11, 12}
	if err := cvGenerateReceiverKeyMaterial(publicDir, secretDir, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}

	registryPath := filepath.Join(publicDir, cvReceiverRegistryFilename)
	registryRaw, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var registry cvReceiverRegistry
	if err := json.Unmarshal(registryRaw, &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Version != cvReceiverRegistryVersion || registry.SID != sid {
		t.Fatalf("registry version/SID = %d/%q", registry.Version, registry.SID)
	}
	if len(registry.Receivers) != len(receiverIDs) {
		t.Fatalf("registry receiver count = %d, want %d", len(registry.Receivers), len(receiverIDs))
	}
	for i, entry := range registry.Receivers {
		if entry.ReceiverID != receiverIDs[i] || entry.ReceiverIndex != i+1 {
			t.Fatalf("registry entry %d = id/index %d/%d", i, entry.ReceiverID, entry.ReceiverIndex)
		}
		encoded, err := hex.DecodeString(entry.PublicKey)
		if err != nil || len(encoded) != 48 {
			t.Fatalf("registry entry %d has invalid compressed G1: %q", i, entry.PublicKey)
		}
		signingEncoded, err := hex.DecodeString(entry.SigningPublicKey)
		if err != nil || len(signingEncoded) != 48 || bytes.Equal(encoded, signingEncoded) {
			t.Fatalf("registry entry %d has invalid or reused signing key", i)
		}
	}
	assertCVKeyFileMode(t, registryPath, 0o644)
	for _, id := range receiverIDs {
		assertCVKeyFileMode(t, cvReceiverSecretPath(secretDir, id), 0o600)
		assertCVKeyFileMode(t, cvReceiverSigningSecretPath(secretDir, id), 0o600)
	}

	// A corrupt non-local secret must not affect this process: strict loading
	// opens only the receiver IDs explicitly assigned to it.
	if err := os.WriteFile(cvReceiverSecretPath(secretDir, 12), []byte("not-a-scalar"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := cvLoadReceiverKeyMaterial(publicDir, secretDir, sid, receiverIDs, []int{11, 10})
	if err != nil {
		t.Fatalf("load local receiver keys: %v", err)
	}
	if len(keys.receiverPublicKeys) != len(receiverIDs) || len(keys.receiverSigningPublicKeys) != len(receiverIDs) ||
		len(keys.localReceiverSecrets) != 2 || len(keys.localReceiverSigningSecrets) != 2 {
		t.Fatalf("loaded public/signing/local key counts = %d/%d/%d/%d", len(keys.receiverPublicKeys), len(keys.receiverSigningPublicKeys), len(keys.localReceiverSecrets), len(keys.localReceiverSigningSecrets))
	}
	if _, ok := keys.localReceiverSecrets[12]; ok {
		t.Fatal("strict loader retained a non-local receiver secret")
	}
	for _, id := range []int{10, 11} {
		secret, ok := keys.localReceiverSecrets[id]
		if !ok {
			t.Fatalf("missing local receiver secret %d", id)
		}
		publicKey, err := cvReceiverPublicKey(secret)
		if err != nil {
			t.Fatal(err)
		}
		if !publicKey.Equal(&keys.receiverPublicKeys[keys.receiverIndex[id]-1]) {
			t.Fatalf("receiver %d secret/public registry mismatch", id)
		}
		signingSecret, ok := keys.localReceiverSigningSecrets[id]
		if !ok || signingSecret.Equal(&secret) {
			t.Fatalf("receiver %d signing secret missing or reused", id)
		}
		signingPublicKey, err := cvReceiverPublicKey(signingSecret)
		if err != nil || !signingPublicKey.Equal(&keys.receiverSigningPublicKeys[keys.receiverIndex[id]-1]) {
			t.Fatalf("receiver %d signing secret/public registry mismatch", id)
		}
	}

	secondRoot := t.TempDir()
	secondPublicDir := filepath.Join(secondRoot, "public")
	secondSecretDir := filepath.Join(secondRoot, "private")
	if err := cvGenerateReceiverKeyMaterial(secondPublicDir, secondSecretDir, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}
	firstSecret, err := os.ReadFile(cvReceiverSecretPath(secretDir, 10))
	if err != nil {
		t.Fatal(err)
	}
	secondSecret, err := os.ReadFile(cvReceiverSecretPath(secondSecretDir, 10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstSecret, secondSecret) {
		t.Fatal("independent key generations reused a receiver scalar")
	}
}

func TestCVReceiverKeyMaterialRejectsMismatchedRegistryAndSecrets(t *testing.T) {
	const sid = "cv-keys-validation"
	receiverIDs := []int{20, 21, 22}

	t.Run("SID", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, "other-session", receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted registry from another SID")
		}
	})

	t.Run("receiver order", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, []int{21, 20, 22}, []int{20}); err == nil {
			t.Fatal("accepted a registry with the wrong receiver order")
		}
	})

	t.Run("unknown local receiver", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{23}); err == nil {
			t.Fatal("accepted a local receiver outside the registry")
		}
	})

	t.Run("noncanonical scalar", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		noncanonical := fr.Modulus().FillBytes(make([]byte, fr.Bytes))
		if err := os.WriteFile(cvReceiverSecretPath(dirs.secret, 20), noncanonical, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a noncanonical receiver scalar")
		}
	})

	t.Run("zero scalar", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := os.WriteFile(cvReceiverSecretPath(dirs.secret, 20), make([]byte, fr.Bytes), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a zero receiver scalar")
		}
	})

	t.Run("secret public mismatch", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		other, err := os.ReadFile(cvReceiverSecretPath(dirs.secret, 21))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cvReceiverSecretPath(dirs.secret, 20), other, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a receiver scalar for another public key")
		}
	})

	t.Run("interpolation index", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		registry := readCVReceiverRegistryForTest(t, dirs.public)
		registry.Receivers[0].ReceiverIndex = 2
		writeCVReceiverRegistryForTest(t, dirs.public, registry)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a receiver with the wrong interpolation index")
		}
	})

	t.Run("public key", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		registry := readCVReceiverRegistryForTest(t, dirs.public)
		registry.Receivers[0].PublicKey = "00"
		writeCVReceiverRegistryForTest(t, dirs.public, registry)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a noncanonical compressed public key")
		}
	})

	t.Run("reused signing public key", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		registry := readCVReceiverRegistryForTest(t, dirs.public)
		registry.Receivers[0].SigningPublicKey = registry.Receivers[0].PublicKey
		writeCVReceiverRegistryForTest(t, dirs.public, registry)
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted a receiver registry that reused the encryption key for signing")
		}
	})

	for _, tc := range []struct {
		name         string
		signingIndex int
		publicIndex  int
	}{
		{name: "signing key reuses later encryption key", signingIndex: 0, publicIndex: 1},
		{name: "signing key reuses earlier encryption key", signingIndex: 1, publicIndex: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
			registry := readCVReceiverRegistryForTest(t, dirs.public)
			registry.Receivers[tc.signingIndex].SigningPublicKey = registry.Receivers[tc.publicIndex].PublicKey
			writeCVReceiverRegistryForTest(t, dirs.public, registry)
			if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
				t.Fatal("accepted cross-receiver encryption/signing key reuse")
			}
		})
	}
}

func TestCVReceiverRegistryDigestBindsReceiverIDs(t *testing.T) {
	const sid = "cv-registry-digest"
	receiverIDs := []int{30, 31, 32}
	dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
	original, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(original.registryDigest) != 32 {
		t.Fatalf("registry digest length = %d, want 32", len(original.registryDigest))
	}

	remappedIDs := []int{40, 41, 42}
	registry := readCVReceiverRegistryForTest(t, dirs.public)
	for i := range registry.Receivers {
		registry.Receivers[i].ReceiverID = remappedIDs[i]
	}
	writeCVReceiverRegistryForTest(t, dirs.public, registry)
	remapped, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, remappedIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original.registryDigest, remapped.registryDigest) {
		t.Fatal("registry digest did not bind receiver IDs")
	}
}

func TestCVReceiverKeyMaterialRejectsUnsafeFiles(t *testing.T) {
	const sid = "cv-keys-files"
	receiverIDs := []int{50, 51}

	t.Run("registry symlink", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilename)
		target := path + ".target"
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted a symlinked receiver registry")
		}
	})

	t.Run("secret symlink", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPath(dirs.secret, 50)
		target := path + ".target"
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted a symlinked receiver secret")
		}
	})

	t.Run("non-regular registry", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilename)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted a non-regular receiver registry")
		}
	})

	t.Run("non-regular secret", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPath(dirs.secret, 50)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted a non-regular receiver secret")
		}
	})

	t.Run("insecure secret mode", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := os.Chmod(cvReceiverSecretPath(dirs.secret, 50), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted an insecure receiver secret mode")
		}
	})

	t.Run("oversized registry", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilename)
		if err := os.WriteFile(path, make([]byte, cvMaxReceiverRegistryBytes+1), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted an oversized receiver registry")
		}
	})

	t.Run("oversized secret", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPath(dirs.secret, 50)
		if err := os.WriteFile(path, make([]byte, fr.Bytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted an oversized receiver secret")
		}
	})

	t.Run("generation does not overwrite", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := cvGenerateReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs); err == nil {
			t.Fatal("key generation overwrote existing material")
		}
	})

	t.Run("loader requires separate directories", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		secret, err := os.ReadFile(cvReceiverSecretPath(dirs.secret, 50))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cvReceiverSecretPath(dirs.public, 50), secret, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterial(dirs.public, dirs.public, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("loader accepted one directory for public and local-secret material")
		}
	})
}

func TestCVOldLockKeyMaterialLoadsOnlyLocalSigningShare(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	members := []int{0, 1, 2, 3}
	if err := cvGenerateOldLockKeyMaterial(publicDir, secretDir, "cv-old-lock", members, 3); err != nil {
		t.Fatal(err)
	}
	material, err := cvLoadOldLockKeyMaterial(publicDir, secretDir, "cv-old-lock", members, 3, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newTBLSThresholdSignerFromMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	sig, err := signer.SignShare(1, "CV_TEST", digest)
	if err != nil || !signer.VerifyShare(1, "CV_TEST", digest, sig) {
		t.Fatalf("local old-node share failed: %v", err)
	}
	if _, err := signer.SignShare(0, "CV_TEST", digest); err == nil {
		t.Fatal("strict old lock signer retained a non-local share")
	}
	if len(material.localShares) != 1 {
		t.Fatalf("loaded old-node secrets = %d, want 1", len(material.localShares))
	}
	peerMaterial, err := cvLoadOldLockKeyMaterial(publicDir, secretDir, "cv-old-lock", members, 3, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	peerSigner, err := newTBLSThresholdSignerFromMaterial(peerMaterial)
	if err != nil {
		t.Fatal(err)
	}
	peerSig, err := peerSigner.SignShare(0, "CV_TEST", digest)
	if err != nil || !signer.VerifyShare(0, "CV_TEST", digest, peerSig) {
		t.Fatalf("public registry could not verify peer share: %v", err)
	}
}

func TestCVMVBACoinKeyMaterialLocalOnlyAndThresholdRecovery(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	members := []int{0, 1, 2, 3}
	const sid = "cv-mvba-coin"
	if err := cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2); err != nil {
		t.Fatal(err)
	}
	assertCVKeyFileMode(t, filepath.Join(publicDir, cvMVBACoinRegistryFilename), 0o644)
	for _, member := range members {
		assertCVKeyFileMode(t, cvMVBACoinSecretPath(secretDir, member), 0o600)
	}

	localOne, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(localOne.localShares) != 1 {
		t.Fatalf("loaded MVBA coin secrets = %d, want 1", len(localOne.localShares))
	}
	signerOne, err := newTBLSThresholdSignerFromCoinMaterial(localOne)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("coin-recovery-test"))
	shareOne, err := signerOne.SignShare(1, "CV_MVBA_COIN_TEST", digest)
	if err != nil || !signerOne.VerifyShare(1, "CV_MVBA_COIN_TEST", digest, shareOne) {
		t.Fatalf("local MVBA coin share failed: %v", err)
	}
	if _, err := signerOne.SignShare(0, "CV_MVBA_COIN_TEST", digest); err == nil {
		t.Fatal("MVBA coin signer retained a non-local share")
	}

	localZero, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	signerZero, err := newTBLSThresholdSignerFromCoinMaterial(localZero)
	if err != nil {
		t.Fatal(err)
	}
	shareZero, err := signerZero.SignShare(0, "CV_MVBA_COIN_TEST", digest)
	if err != nil || !signerOne.VerifyShare(0, "CV_MVBA_COIN_TEST", digest, shareZero) {
		t.Fatalf("peer MVBA coin share failed: %v", err)
	}
	recovered, err := signerOne.Recover("CV_MVBA_COIN_TEST", digest, map[int][]byte{0: shareZero, 1: shareOne})
	if err != nil || !signerOne.VerifyRecovered("CV_MVBA_COIN_TEST", digest, recovered) {
		t.Fatalf("recover MVBA threshold coin signature: %v", err)
	}
	if _, err := signerOne.Recover("CV_MVBA_COIN_TEST", digest, map[int][]byte{1: shareOne}); err == nil {
		t.Fatal("MVBA coin recovered below f+1 threshold")
	}

	for _, member := range []int{0, 2, 3} {
		if err := os.Remove(cvMVBACoinSecretPath(secretDir, member)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{1}); err != nil {
		t.Fatalf("loader required non-local MVBA coin secrets: %v", err)
	}
}

func TestCVMVBACoinKeyMaterialRejectsInvalidArtifacts(t *testing.T) {
	members := []int{0, 1, 2, 3}
	const sid = "cv-mvba-coin-invalid"

	t.Run("context mismatch", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, "wrong-sid", members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted wrong SID")
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 3, []int{0}); err == nil {
			t.Fatal("loader accepted wrong threshold")
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, []int{1, 0, 2, 3}, 2, []int{0}); err == nil {
			t.Fatal("loader accepted wrong member order")
		}
	})

	t.Run("mutated public polynomial", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := filepath.Join(publicDir, cvMVBACoinRegistryFilename)
		registry := readCVMVBACoinRegistryForTest(t, path)
		registry.Members[0].PublicKey = registry.Members[1].PublicKey
		writeJSONForTest(t, path, registry, 0o644)
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted inconsistent public polynomial")
		}
	})

	t.Run("registry digest binding", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := filepath.Join(publicDir, cvMVBACoinRegistryFilename)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted private share bound to a different registry encoding")
		}
	})

	t.Run("mutated private share", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := cvMVBACoinSecretPath(secretDir, 0)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var artifact cvMVBACoinPrivateArtifact
		if err := json.Unmarshal(raw, &artifact); err != nil {
			t.Fatal(err)
		}
		artifact.Share = hex.EncodeToString(make([]byte, fr.Bytes))
		writeJSONForTest(t, path, artifact, 0o600)
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted mutated private share")
		}
	})

	t.Run("insecure private permissions", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := cvMVBACoinSecretPath(secretDir, 0)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted insecure private permissions")
		}
	})

	t.Run("private symlink", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := cvMVBACoinSecretPath(secretDir, 0)
		target := filepath.Join(secretDir, "coin-target")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader followed a private key symlink")
		}
	})

	t.Run("oversized private artifact", func(t *testing.T) {
		publicDir, secretDir := generateCVMVBACoinKeysForTest(t, sid, members, 2)
		path := cvMVBACoinSecretPath(secretDir, 0)
		if err := os.WriteFile(path, make([]byte, cvMaxReceiverRegistryBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadMVBACoinKeyMaterial(publicDir, secretDir, sid, members, 2, []int{0}); err == nil {
			t.Fatal("loader accepted oversized private artifact")
		}
	})
}

func TestCVRuntimeUsesRegistryBoundOldLockSigner(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	oldMembers := []int{0, 1, 2, 3}
	newMembers := []int{4, 5, 6, 7}
	if err := cvGenerateReceiverKeyMaterial(publicDir, secretDir, "cv-runtime-lock", newMembers); err != nil {
		t.Fatal(err)
	}
	if err := cvGenerateOldLockKeyMaterial(publicDir, secretDir, "cv-runtime-lock", oldMembers, 3); err != nil {
		t.Fatal(err)
	}
	if err := cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, "cv-runtime-lock", oldMembers, 2); err != nil {
		t.Fatal(err)
	}
	cfg := NormalizeConfig(Config{
		SID: "cv-runtime-lock", OldCommittee: oldMembers, NewCommittee: newMembers, FOld: 1, FNew: 1,
		LocalNodeIDs:   []int{2},
		CVPublicKeyDir: publicDir, CVLocalSecretDir: secretDir,
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := cfg.runtime.lockSigner.SignShare(2, "CV_RUNTIME_TEST", digest); err != nil {
		t.Fatalf("local registry share rejected: %v", err)
	}
	if _, err := cfg.runtime.lockSigner.SignShare(0, "CV_RUNTIME_TEST", digest); err == nil {
		t.Fatal("CV runtime fell back to a signer containing non-local old-node shares")
	}
	if _, err := cfg.runtime.coinSigner.SignShare(2, "CV_RUNTIME_COIN_TEST", digest); err != nil {
		t.Fatalf("local registry coin share rejected: %v", err)
	}
	if _, err := cfg.runtime.coinSigner.SignShare(0, "CV_RUNTIME_COIN_TEST", digest); err == nil {
		t.Fatal("CV runtime retained a non-local MVBA coin share")
	}
}

func TestCVSetupBundleDigestBindsAllPublicRegistries(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	oldMembers := []int{0, 1, 2, 3}
	newMembers := []int{4, 5, 6, 7}
	if err := cvGenerateReceiverKeyMaterial(publicDir, secretDir, "cv-setup-digest", newMembers); err != nil {
		t.Fatal(err)
	}
	if err := cvGenerateOldLockKeyMaterial(publicDir, secretDir, "cv-setup-digest", oldMembers, 3); err != nil {
		t.Fatal(err)
	}
	if err := cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, "cv-setup-digest", oldMembers, 2); err != nil {
		t.Fatal(err)
	}
	digest, err := CVSetupBundleDigest(publicDir)
	if err != nil || digest == "" {
		t.Fatalf("setup digest failed: digest=%q err=%v", digest, err)
	}
	path := filepath.Join(publicDir, cvMVBACoinRegistryFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	mutated, err := CVSetupBundleDigest(publicDir)
	if err != nil {
		t.Fatal(err)
	}
	if mutated == digest {
		t.Fatal("setup digest did not bind MVBA coin registry")
	}
}

type cvReceiverKeyDirsForTest struct {
	public string
	secret string
}

func generateCVReceiverKeysForTest(t testing.TB, sid string, receiverIDs []int) cvReceiverKeyDirsForTest {
	t.Helper()
	root := t.TempDir()
	dirs := cvReceiverKeyDirsForTest{
		public: filepath.Join(root, "public"),
		secret: filepath.Join(root, "private"),
	}
	if err := cvGenerateReceiverKeyMaterial(dirs.public, dirs.secret, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func generateCVMVBACoinKeysForTest(t testing.TB, sid string, members []int, threshold int) (string, string) {
	t.Helper()
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	if err := cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, sid, members, threshold); err != nil {
		t.Fatal(err)
	}
	return publicDir, secretDir
}

func readCVMVBACoinRegistryForTest(t testing.TB, path string) cvMVBACoinRegistry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var registry cvMVBACoinRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	return registry
}

func writeJSONForTest(t testing.TB, path string, value any, mode os.FileMode) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}

func readCVReceiverRegistryForTest(t testing.TB, dir string) cvReceiverRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, cvReceiverRegistryFilename))
	if err != nil {
		t.Fatal(err)
	}
	var registry cvReceiverRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	return registry
}

func writeCVReceiverRegistryForTest(t testing.TB, dir string, registry cvReceiverRegistry) {
	t.Helper()
	raw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cvReceiverRegistryFilename), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertCVKeyFileMode(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
