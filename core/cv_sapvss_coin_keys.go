package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvMVBACoinRegistryFilename     = "mvba-coin-registry.json"
	cvMVBACoinRegistryVersion      = 1
	cvMVBACoinPrivateVersion       = 1
	cvMVBACoinRegistryDigestDomain = "ARL-ADKR/MVBA-coin-registry/v1"
)

type cvMVBACoinRegistryEntry struct {
	MemberID   int    `json:"member_id"`
	ShareIndex int    `json:"share_index"`
	PublicKey  string `json:"public_key"`
}

type cvMVBACoinRegistry struct {
	Version        int                       `json:"version"`
	SID            string                    `json:"sid"`
	Threshold      int                       `json:"threshold"`
	GroupPublicKey string                    `json:"group_public_key"`
	Members        []cvMVBACoinRegistryEntry `json:"members"`
}

type cvMVBACoinPrivateArtifact struct {
	Version        int    `json:"version"`
	MemberID       int    `json:"member_id"`
	ShareIndex     int    `json:"share_index"`
	RegistryDigest string `json:"registry_digest"`
	Share          string `json:"share"`
}

type cvMVBACoinKeyMaterial struct {
	members      []int
	threshold    int
	groupPublic  bls12381.G2Affine
	publicShares []bls12381.G2Affine
	localShares  map[int]fr.Element
}

func GenerateCVMVBACoinKeyMaterial(publicDir, secretDir, sid string, members []int, threshold int) error {
	return cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, sid, members, threshold)
}

func cvMVBACoinSecretPath(dir string, member int) string {
	return filepath.Join(dir, fmt.Sprintf("old-node-%d-coin.scalar", member))
}

func cvGenerateMVBACoinKeyMaterial(publicDir, secretDir, sid string, members []int, threshold int) error {
	if publicDir == "" || secretDir == "" || sid == "" || threshold <= 0 || threshold > len(members) {
		return fmt.Errorf("invalid CV MVBA coin key generation parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return err
	}
	if err := cvValidateDistinctReceiverIDs(members, false); err != nil {
		return err
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(secretDir, 0o700); err != nil {
		return err
	}
	registryPath := filepath.Join(publicDir, cvMVBACoinRegistryFilename)
	paths := []string{registryPath}
	for _, member := range members {
		paths = append(paths, cvMVBACoinSecretPath(secretDir, member))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV MVBA coin key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	var coefficients, shares []fr.Element
	for {
		coefficients = make([]fr.Element, threshold)
		for i := range coefficients {
			if _, err := coefficients[i].SetRandom(); err != nil {
				return fmt.Errorf("sample CV MVBA coin coefficient: %w", err)
			}
		}
		if coefficients[0].IsZero() || (threshold > 1 && coefficients[threshold-1].IsZero()) {
			continue
		}
		shares = make([]fr.Element, len(members))
		valid := true
		for i := range shares {
			shares[i] = evalPolyInt(coefficients, int64(i+1))
			if shares[i].IsZero() {
				valid = false
				break
			}
		}
		if valid {
			break
		}
	}

	var groupPublic bls12381.G2Affine
	groupPublic.ScalarMultiplication(&genG2, coefficients[0].BigInt(new(big.Int)))
	groupBytes := groupPublic.Bytes()
	registry := cvMVBACoinRegistry{
		Version: cvMVBACoinRegistryVersion, SID: sid, Threshold: threshold,
		GroupPublicKey: hex.EncodeToString(groupBytes[:]),
		Members:        make([]cvMVBACoinRegistryEntry, len(members)),
	}
	for i, member := range members {
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, shares[i].BigInt(new(big.Int)))
		encoded := publicShare.Bytes()
		registry.Members[i] = cvMVBACoinRegistryEntry{
			MemberID: member, ShareIndex: i + 1, PublicKey: hex.EncodeToString(encoded[:]),
		}
	}
	registryRaw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	registryRaw = append(registryRaw, '\n')
	registryDigest := hashBytes([]byte(cvMVBACoinRegistryDigestDomain), registryRaw)

	created := make([]string, 0, len(members)+1)
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for i, member := range members {
		shareBytes := shares[i].Bytes()
		artifact := cvMVBACoinPrivateArtifact{
			Version: cvMVBACoinPrivateVersion, MemberID: member, ShareIndex: i + 1,
			RegistryDigest: hex.EncodeToString(registryDigest), Share: hex.EncodeToString(shareBytes[:]),
		}
		raw, marshalErr := json.Marshal(artifact)
		if marshalErr != nil {
			cleanup()
			return marshalErr
		}
		path := cvMVBACoinSecretPath(secretDir, member)
		if err := cvWriteExclusiveKeyFile(path, raw, 0o600); err != nil {
			cleanup()
			return err
		}
		created = append(created, path)
	}
	if err := cvWriteExclusiveKeyFile(registryPath, registryRaw, 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func cvLoadMVBACoinKeyMaterial(
	publicDir, secretDir, sid string,
	expectedMembers []int,
	threshold int,
	localMembers []int,
) (*cvMVBACoinKeyMaterial, error) {
	if publicDir == "" || secretDir == "" || sid == "" || threshold <= 0 || threshold > len(expectedMembers) {
		return nil, fmt.Errorf("invalid CV MVBA coin key loading parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(expectedMembers, false); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(localMembers, false); err != nil {
		return nil, err
	}
	registryRaw, err := cvReadBoundedRegularFile(
		filepath.Join(publicDir, cvMVBACoinRegistryFilename), cvMaxReceiverRegistryBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read CV MVBA coin registry: %w", err)
	}
	var registry cvMVBACoinRegistry
	decoder := json.NewDecoder(bytes.NewReader(registryRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, fmt.Errorf("decode CV MVBA coin registry: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV MVBA coin registry suffix")
	}
	if registry.Version != cvMVBACoinRegistryVersion || registry.SID != sid ||
		registry.Threshold != threshold || len(registry.Members) != len(expectedMembers) {
		return nil, fmt.Errorf("CV MVBA coin registry context mismatch")
	}
	groupPublic, err := cvDecodeCanonicalG2(registry.GroupPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid CV MVBA coin group public key: %w", err)
	}
	material := &cvMVBACoinKeyMaterial{
		members: append([]int(nil), expectedMembers...), threshold: threshold,
		groupPublic: groupPublic, publicShares: make([]bls12381.G2Affine, len(expectedMembers)),
		localShares: make(map[int]fr.Element, len(localMembers)),
	}
	memberIndex := make(map[int]int, len(expectedMembers))
	for i, entry := range registry.Members {
		if entry.MemberID != expectedMembers[i] || entry.ShareIndex != i+1 {
			return nil, fmt.Errorf("CV MVBA coin registry order/index mismatch")
		}
		publicShare, err := cvDecodeCanonicalG2(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid CV MVBA coin public share %d: %w", i+1, err)
		}
		material.publicShares[i] = publicShare
		memberIndex[entry.MemberID] = i
	}
	baseIndices := make([]int, threshold)
	basePoints := make([]bls12381.G2Affine, threshold)
	for i := 0; i < threshold; i++ {
		baseIndices[i] = i + 1
		basePoints[i] = material.publicShares[i]
	}
	constant, err := cvInterpolateG2At(baseIndices, basePoints, 0)
	if err != nil || !constant.Equal(&material.groupPublic) {
		return nil, fmt.Errorf("CV MVBA coin group key is inconsistent with public shares")
	}
	for i := threshold; i < len(material.publicShares); i++ {
		expected, err := cvInterpolateG2At(baseIndices, basePoints, i+1)
		if err != nil || !expected.Equal(&material.publicShares[i]) {
			return nil, fmt.Errorf("CV MVBA coin public shares are not a degree-%d polynomial", threshold-1)
		}
	}

	registryDigest := hex.EncodeToString(hashBytes([]byte(cvMVBACoinRegistryDigestDomain), registryRaw))
	for _, member := range localMembers {
		index, ok := memberIndex[member]
		if !ok {
			return nil, fmt.Errorf("local MVBA coin member %d is outside registry", member)
		}
		raw, err := cvReadPrivateKeyArtifact(cvMVBACoinSecretPath(secretDir, member), cvMaxReceiverRegistryBytes)
		if err != nil {
			return nil, fmt.Errorf("read local MVBA coin secret %d: %w", member, err)
		}
		var artifact cvMVBACoinPrivateArtifact
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&artifact); err != nil {
			return nil, fmt.Errorf("decode local MVBA coin secret %d: %w", member, err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("invalid local MVBA coin secret suffix for %d", member)
		}
		if artifact.Version != cvMVBACoinPrivateVersion || artifact.MemberID != member ||
			artifact.ShareIndex != index+1 || artifact.RegistryDigest != registryDigest {
			return nil, fmt.Errorf("local MVBA coin secret context mismatch for %d", member)
		}
		shareBytes, err := hex.DecodeString(artifact.Share)
		if err != nil || len(shareBytes) != fr.Bytes || hex.EncodeToString(shareBytes) != artifact.Share {
			return nil, fmt.Errorf("invalid local MVBA coin secret encoding for %d", member)
		}
		var share fr.Element
		if err := share.SetBytesCanonical(shareBytes); err != nil || share.IsZero() {
			return nil, fmt.Errorf("invalid local MVBA coin secret scalar for %d", member)
		}
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, share.BigInt(new(big.Int)))
		if !publicShare.Equal(&material.publicShares[index]) {
			return nil, fmt.Errorf("local MVBA coin secret/public mismatch for %d", member)
		}
		material.localShares[member] = share
	}
	return material, nil
}

func cvReadPrivateKeyArtifact(path string, maximum int64) ([]byte, error) {
	file, info, err := cvOpenRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("CV private key artifact must have mode 0600: %s", path)
	}
	if maximum <= 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("CV private key artifact exceeds size bound: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size() || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("CV private key artifact changed size while reading: %s", path)
	}
	return raw, nil
}
