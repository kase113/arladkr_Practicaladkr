package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const practicalSetupManifestVersion = 1

type practicalSetupFileDigest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type practicalSetupNodeManifest struct {
	OldNodeID    int      `json:"old_node_id"`
	NewNodeID    int      `json:"new_node_id"`
	PrivateFiles []string `json:"private_files"`
}

type practicalSetupManifest struct {
	Version      int                          `json:"version"`
	SID          string                       `json:"sid"`
	OldCommittee []int                        `json:"old_committee"`
	NewCommittee []int                        `json:"new_committee"`
	F            int                          `json:"f"`
	PaillierBits int                          `json:"paillier_bits"`
	PublicFiles  []practicalSetupFileDigest   `json:"public_files"`
	Nodes        []practicalSetupNodeManifest `json:"nodes"`
	BundleDigest string                       `json:"bundle_digest"`
}

func practicalSetupReadOnly() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PRACTICAL_SETUP_READ_ONLY")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// GeneratePracticalSetupProvision creates trusted offline benchmark material.
// The returned tree has one public bundle and one owner-local cache per old node.
func GeneratePracticalSetupProvision(outputDir string, cfg Config) (string, error) {
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" || strings.TrimSpace(cfg.SID) == "" {
		return "", fmt.Errorf("invalid Practical setup output")
	}
	old := append([]int(nil), cfg.OldCommittee...)
	newC := append([]int(nil), cfg.NewCommittee...)
	sort.Ints(old)
	sort.Ints(newC)
	if len(old) == 0 || len(old) != len(newC) || cfg.F < 0 || len(old) < 3*cfg.F+1 {
		return "", fmt.Errorf("invalid Practical setup committees")
	}
	bits := cfg.PaillierBits
	if bits <= 0 {
		bits = 3072
	}
	if entries, err := os.ReadDir(outputDir); err == nil && len(entries) != 0 {
		return "", fmt.Errorf("Practical setup output must be empty: %s", outputDir)
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return "", err
	}
	generatedDir := filepath.Join(outputDir, ".generated")
	if err := os.Mkdir(generatedDir, 0o700); err != nil {
		return "", err
	}
	committed := false
	cleanup := func() {
		if !committed {
			_ = os.RemoveAll(outputDir)
		}
	}
	defer cleanup()

	signingPublic := practicalSigningPublicPath(generatedDir, old, newC)
	if err := generatePracticalSigningArtifacts(signingPublic, old, newC); err != nil {
		return "", err
	}
	paillierPub, paillierPriv, err := generateRecipientPaillierKeys(newC, bits)
	if err != nil {
		return "", err
	}
	paillierPublic := filepath.Join(generatedDir, paillierCacheFileName(Config{SID: cfg.SID, PaillierBits: bits}, newC)) + ".public.json"
	for id, private := range paillierPriv {
		if err := writePaillierPrivateCache(paillierPrivateCachePath(paillierPublic, id), id, private); err != nil {
			return "", err
		}
	}
	if err := writePaillierPublicCache(paillierPublic, paillierPub); err != nil {
		return "", err
	}
	compKeys, err := generatePracticalCompKeys(newC)
	if err != nil {
		return "", err
	}
	compPublic := practicalCompPublicPath(generatedDir, newC)
	if err := writePracticalCompArtifacts(compPublic, compKeys); err != nil {
		return "", err
	}
	coinKeys, err := generateThresholdCoinKeys(old, cfg.F)
	if err != nil {
		return "", err
	}
	coinPublic := thresholdCoinPublicPath(generatedDir, old, cfg.F)
	if err := writeThresholdCoinArtifacts(coinPublic, coinKeys); err != nil {
		return "", err
	}

	publicPaths := []string{signingPublic, paillierPublic, compPublic, coinPublic}
	sort.Strings(publicPaths)
	manifest := practicalSetupManifest{
		Version: practicalSetupManifestVersion, SID: cfg.SID,
		OldCommittee: old, NewCommittee: newC, F: cfg.F, PaillierBits: bits,
		PublicFiles: make([]practicalSetupFileDigest, 0, len(publicPaths)),
		Nodes:       make([]practicalSetupNodeManifest, 0, len(old)),
	}
	publicDir := filepath.Join(outputDir, "public")
	if err := os.Mkdir(publicDir, 0o755); err != nil {
		return "", err
	}
	for _, path := range publicPaths {
		name := filepath.Base(path)
		digest, err := practicalCopySetupFile(path, filepath.Join(publicDir, name), 0o644)
		if err != nil {
			return "", err
		}
		manifest.PublicFiles = append(manifest.PublicFiles, practicalSetupFileDigest{Name: name, SHA256: digest})
	}

	for i, oldID := range old {
		newID := newC[i]
		privatePaths := []string{
			practicalSigningPrivatePath(signingPublic, dealerECDSARole, oldID),
			practicalSigningPrivatePath(signingPublic, oldEd25519Role, oldID),
			practicalSigningPrivatePath(signingPublic, recipientECDSARole, newID),
			paillierPrivateCachePath(paillierPublic, newID),
			practicalCompPrivatePath(compPublic, newID),
			thresholdCoinPrivatePath(coinPublic, oldID),
		}
		sort.Strings(privatePaths)
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("node-%06d", oldID))
		if err := os.Mkdir(nodeDir, 0o700); err != nil {
			return "", err
		}
		for _, path := range publicPaths {
			if _, err := practicalCopySetupFile(path, filepath.Join(nodeDir, filepath.Base(path)), 0o644); err != nil {
				return "", err
			}
		}
		nodeManifest := practicalSetupNodeManifest{OldNodeID: oldID, NewNodeID: newID}
		for _, path := range privatePaths {
			name := filepath.Base(path)
			if _, err := practicalCopySetupFile(path, filepath.Join(nodeDir, name), 0o600); err != nil {
				return "", err
			}
			nodeManifest.PrivateFiles = append(nodeManifest.PrivateFiles, name)
		}
		manifest.Nodes = append(manifest.Nodes, nodeManifest)
	}
	manifest.BundleDigest, err = practicalManifestBundleDigest(manifest)
	if err != nil {
		return "", err
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := practicalWriteSetupFile(filepath.Join(publicDir, "setup-manifest.json"), manifestRaw, 0o644); err != nil {
		return "", err
	}
	for _, node := range manifest.Nodes {
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("node-%06d", node.OldNodeID))
		if err := practicalWriteSetupFile(filepath.Join(nodeDir, "setup-manifest.json"), manifestRaw, 0o644); err != nil {
			return "", err
		}
	}
	if err := os.RemoveAll(generatedDir); err != nil {
		return "", err
	}
	committed = true
	return manifest.BundleDigest, nil
}

func VerifyPracticalSetupProvision(cacheDir string, cfg Config) (string, error) {
	raw, err := os.ReadFile(filepath.Join(cacheDir, "setup-manifest.json"))
	if err != nil {
		return "", fmt.Errorf("read Practical setup manifest: %w", err)
	}
	var manifest practicalSetupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", fmt.Errorf("decode Practical setup manifest: %w", err)
	}
	old := append([]int(nil), cfg.OldCommittee...)
	newC := append([]int(nil), cfg.NewCommittee...)
	sort.Ints(old)
	sort.Ints(newC)
	bits := cfg.PaillierBits
	if bits <= 0 {
		bits = 3072
	}
	if manifest.Version != practicalSetupManifestVersion || manifest.SID != cfg.SID ||
		manifest.F != cfg.F || manifest.PaillierBits != bits ||
		!equalIntSlices(manifest.OldCommittee, old) || !equalIntSlices(manifest.NewCommittee, newC) {
		return "", fmt.Errorf("Practical setup manifest context mismatch")
	}
	expectedPublic, expectedNodes, err := practicalExpectedSetupFiles(cacheDir, cfg.SID, old, newC, cfg.F, bits)
	if err != nil {
		return "", err
	}
	if len(manifest.PublicFiles) != len(expectedPublic) || len(manifest.Nodes) != len(expectedNodes) {
		return "", fmt.Errorf("Practical setup manifest file inventory mismatch")
	}
	wantDigest, err := practicalManifestBundleDigest(manifest)
	if err != nil || wantDigest != manifest.BundleDigest {
		return "", fmt.Errorf("Practical setup bundle digest mismatch")
	}
	seenPublic := make(map[string]struct{}, len(manifest.PublicFiles))
	for _, file := range manifest.PublicFiles {
		if filepath.Base(file.Name) != file.Name || file.Name == "" {
			return "", fmt.Errorf("invalid Practical public setup filename")
		}
		if _, ok := expectedPublic[file.Name]; !ok {
			return "", fmt.Errorf("unexpected Practical public setup file: %s", file.Name)
		}
		if _, duplicate := seenPublic[file.Name]; duplicate {
			return "", fmt.Errorf("duplicate Practical public setup file: %s", file.Name)
		}
		seenPublic[file.Name] = struct{}{}
		info, err := os.Lstat(filepath.Join(cacheDir, file.Name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("invalid Practical public setup file: %s", file.Name)
		}
		raw, err := os.ReadFile(filepath.Join(cacheDir, file.Name))
		if err != nil {
			return "", fmt.Errorf("read Practical public setup file %s: %w", file.Name, err)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return "", fmt.Errorf("Practical public setup digest mismatch: %s", file.Name)
		}
	}
	local := thresholdCoinLocalOldIDs(cfg, old)
	if len(local) == 0 {
		return "", fmt.Errorf("Practical setup has no local old identity")
	}
	allowed := make(map[string]struct{})
	seenNodes := make(map[int]struct{}, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		if _, duplicate := seenNodes[node.OldNodeID]; duplicate {
			return "", fmt.Errorf("duplicate Practical setup node %d", node.OldNodeID)
		}
		seenNodes[node.OldNodeID] = struct{}{}
		expected, ok := expectedNodes[node.OldNodeID]
		if !ok || node.NewNodeID != expected.NewNodeID || len(node.PrivateFiles) != len(expected.PrivateFiles) {
			return "", fmt.Errorf("Practical setup node inventory mismatch: %d", node.OldNodeID)
		}
		wantPrivate := make(map[string]struct{}, len(expected.PrivateFiles))
		for _, name := range expected.PrivateFiles {
			wantPrivate[name] = struct{}{}
		}
		for _, name := range node.PrivateFiles {
			if name == "" || filepath.Base(name) != name {
				return "", fmt.Errorf("invalid Practical private setup filename")
			}
			if _, ok := wantPrivate[name]; !ok {
				return "", fmt.Errorf("unexpected Practical private setup file: %s", name)
			}
			delete(wantPrivate, name)
		}
		if len(wantPrivate) != 0 {
			return "", fmt.Errorf("Practical setup node %d is missing private files", node.OldNodeID)
		}
	}
	for _, localID := range local {
		found := false
		for _, node := range manifest.Nodes {
			if node.OldNodeID != localID {
				continue
			}
			found = true
			for _, name := range node.PrivateFiles {
				info, err := os.Lstat(filepath.Join(cacheDir, name))
				if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
					return "", fmt.Errorf("invalid owner-local Practical setup file: %s", name)
				}
				allowed[name] = struct{}{}
			}
		}
		if !found {
			return "", fmt.Errorf("Practical setup manifest missing local node %d", localID)
		}
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".private.json") {
			if _, ok := allowed[entry.Name()]; !ok {
				return "", fmt.Errorf("Practical setup cache contains non-local private artifact: %s", entry.Name())
			}
		}
	}
	return manifest.BundleDigest, nil
}

func practicalExpectedSetupFiles(cacheDir, sid string, old, newC []int, f, bits int) (map[string]struct{}, map[int]practicalSetupNodeManifest, error) {
	if len(old) != len(newC) {
		return nil, nil, fmt.Errorf("Practical setup committee length mismatch")
	}
	signingPublic := practicalSigningPublicPath(cacheDir, old, newC)
	paillierPublic := filepath.Join(cacheDir, paillierCacheFileName(Config{SID: sid, PaillierBits: bits}, newC)) + ".public.json"
	compPublic := practicalCompPublicPath(cacheDir, newC)
	coinPublic := thresholdCoinPublicPath(cacheDir, old, f)
	publicPaths := []string{signingPublic, paillierPublic, compPublic, coinPublic}
	public := make(map[string]struct{}, len(publicPaths))
	for _, path := range publicPaths {
		public[filepath.Base(path)] = struct{}{}
	}
	nodes := make(map[int]practicalSetupNodeManifest, len(old))
	for i, oldID := range old {
		newID := newC[i]
		privatePaths := []string{
			practicalSigningPrivatePath(signingPublic, dealerECDSARole, oldID),
			practicalSigningPrivatePath(signingPublic, oldEd25519Role, oldID),
			practicalSigningPrivatePath(signingPublic, recipientECDSARole, newID),
			paillierPrivateCachePath(paillierPublic, newID),
			practicalCompPrivatePath(compPublic, newID),
			thresholdCoinPrivatePath(coinPublic, oldID),
		}
		privateFiles := make([]string, len(privatePaths))
		for j, path := range privatePaths {
			privateFiles[j] = filepath.Base(path)
		}
		sort.Strings(privateFiles)
		nodes[oldID] = practicalSetupNodeManifest{OldNodeID: oldID, NewNodeID: newID, PrivateFiles: privateFiles}
	}
	return public, nodes, nil
}

func practicalManifestBundleDigest(manifest practicalSetupManifest) (string, error) {
	input := struct {
		Version      int                          `json:"version"`
		SID          string                       `json:"sid"`
		OldCommittee []int                        `json:"old_committee"`
		NewCommittee []int                        `json:"new_committee"`
		F            int                          `json:"f"`
		PaillierBits int                          `json:"paillier_bits"`
		PublicFiles  []practicalSetupFileDigest   `json:"public_files"`
		Nodes        []practicalSetupNodeManifest `json:"nodes"`
	}{manifest.Version, manifest.SID, manifest.OldCommittee, manifest.NewCommittee, manifest.F, manifest.PaillierBits, manifest.PublicFiles, manifest.Nodes}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("PRACTICAL-ADKR/SETUP-BUNDLE/v1\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func practicalWriteSetupFile(path string, raw []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func practicalCopySetupFile(source, destination string, mode os.FileMode) (string, error) {
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
