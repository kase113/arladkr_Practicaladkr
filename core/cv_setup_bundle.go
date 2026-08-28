package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// CVSetupBundleDigest identifies the public trusted-setup bundle shared by
// every process. Owner-local secret contents are deliberately not included.
func CVSetupBundleDigest(publicDir string) (string, error) {
	return cvSetupBundleDigest(publicDir, "ARL-ADKR/CV-SETUP-BUNDLE/v1\x00", []string{
		cvReceiverRegistryFilename, cvOldLockRegistryFilename, cvMVBACoinRegistryFilename,
	})
}

// CVV2SetupBundleDigest identifies the three epoch-bound public registries
// used by the scalar/group V2 protocol.
func CVV2SetupBundleDigest(publicDir string) (string, error) {
	return cvSetupBundleDigest(publicDir, "ARL-ADKR/CV-V2-SETUP-BUNDLE/v1\x00", []string{
		cvReceiverRegistryV2Filename, cvValidatorRegistryV2Filename, cvOldCommitteeKeyBundleV2Filename,
	})
}

func cvSetupBundleDigest(publicDir, domain string, names []string) (string, error) {
	if publicDir == "" {
		return "", fmt.Errorf("CV setup public directory is empty")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	for _, name := range names {
		path := filepath.Join(publicDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("inspect CV setup registry %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("CV setup registry is not a regular file: %s", name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read CV setup registry %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		fileDigest := sha256.Sum256(raw)
		_, _ = h.Write(fileDigest[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
