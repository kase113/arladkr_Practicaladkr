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
	cvOldLockRegistryFilename = "old-lock-registry.json"
	cvOldLockRegistryVersion  = 2
)

type cvOldLockRegistryEntry struct {
	MemberID           int    `json:"member_id"`
	ShareIndex         int    `json:"share_index"`
	PublicKey          string `json:"public_key"`
	TransportPublicKey string `json:"transport_public_key"`
}

type cvOldLockRegistry struct {
	Version        int                      `json:"version"`
	SID            string                   `json:"sid"`
	Threshold      int                      `json:"threshold"`
	GroupPublicKey string                   `json:"group_public_key"`
	Members        []cvOldLockRegistryEntry `json:"members"`
}

type cvOldLockKeyMaterial struct {
	members               []int
	threshold             int
	groupPublic           bls12381.G2Affine
	publicShares          []bls12381.G2Affine
	transportPublicShares []bls12381.G1Affine
	localShares           map[int]fr.Element
}

func GenerateCVOldLockKeyMaterial(publicDir, secretDir, sid string, members []int, threshold int) error {
	return cvGenerateOldLockKeyMaterial(publicDir, secretDir, sid, members, threshold)
}

func cvOldLockSecretPath(dir string, member int) string {
	return filepath.Join(dir, fmt.Sprintf("old-node-%d-lock.scalar", member))
}

func cvGenerateOldLockKeyMaterial(publicDir, secretDir, sid string, members []int, threshold int) error {
	if publicDir == "" || secretDir == "" || sid == "" || threshold <= 0 || threshold > len(members) {
		return fmt.Errorf("invalid CV old-lock key generation parameters")
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
	registryPath := filepath.Join(publicDir, cvOldLockRegistryFilename)
	paths := []string{registryPath}
	for _, member := range members {
		paths = append(paths, cvOldLockSecretPath(secretDir, member))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV old-lock key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	var coefficients, shares []fr.Element
	for {
		coefficients = make([]fr.Element, threshold)
		for i := range coefficients {
			if _, err := coefficients[i].SetRandom(); err != nil {
				return err
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
	registry := cvOldLockRegistry{
		Version: cvOldLockRegistryVersion, SID: sid, Threshold: threshold,
		GroupPublicKey: hex.EncodeToString(groupBytes[:]),
		Members:        make([]cvOldLockRegistryEntry, len(members)),
	}
	for i, member := range members {
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, shares[i].BigInt(new(big.Int)))
		encoded := publicShare.Bytes()
		var transportPublicShare bls12381.G1Affine
		transportPublicShare.ScalarMultiplication(&genG1, shares[i].BigInt(new(big.Int)))
		transportEncoded := transportPublicShare.Bytes()
		registry.Members[i] = cvOldLockRegistryEntry{
			MemberID: member, ShareIndex: i + 1, PublicKey: hex.EncodeToString(encoded[:]),
			TransportPublicKey: hex.EncodeToString(transportEncoded[:]),
		}
	}
	raw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	created := make([]string, 0, len(members)+1)
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for i, member := range members {
		encoded := shares[i].Bytes()
		path := cvOldLockSecretPath(secretDir, member)
		if err := cvWriteExclusiveKeyFile(path, encoded[:], 0o600); err != nil {
			cleanup()
			return err
		}
		created = append(created, path)
	}
	if err := cvWriteExclusiveKeyFile(registryPath, raw, 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func cvLoadOldLockKeyMaterial(
	publicDir, secretDir, sid string,
	expectedMembers []int,
	threshold int,
	localMembers []int,
) (*cvOldLockKeyMaterial, error) {
	if publicDir == "" || secretDir == "" || sid == "" || threshold <= 0 || threshold > len(expectedMembers) {
		return nil, fmt.Errorf("invalid CV old-lock key loading parameters")
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
	raw, err := cvReadBoundedRegularFile(filepath.Join(publicDir, cvOldLockRegistryFilename), cvMaxReceiverRegistryBytes)
	if err != nil {
		return nil, fmt.Errorf("read CV old-lock registry: %w", err)
	}
	var registry cvOldLockRegistry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV old-lock registry suffix")
	}
	if registry.Version != cvOldLockRegistryVersion || registry.SID != sid ||
		registry.Threshold != threshold || len(registry.Members) != len(expectedMembers) {
		return nil, fmt.Errorf("CV old-lock registry context mismatch")
	}
	groupPublic, err := cvDecodeCanonicalG2(registry.GroupPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid CV old-lock group public key: %w", err)
	}
	material := &cvOldLockKeyMaterial{
		members: append([]int(nil), expectedMembers...), threshold: threshold,
		groupPublic: groupPublic, publicShares: make([]bls12381.G2Affine, len(expectedMembers)),
		transportPublicShares: make([]bls12381.G1Affine, len(expectedMembers)),
		localShares:           make(map[int]fr.Element, len(localMembers)),
	}
	memberIndex := make(map[int]int, len(expectedMembers))
	pairingG1 := make([]bls12381.G1Affine, 0, 2*len(expectedMembers))
	pairingG2 := make([]bls12381.G2Affine, 0, 2*len(expectedMembers))
	for i, entry := range registry.Members {
		if entry.MemberID != expectedMembers[i] || entry.ShareIndex != i+1 {
			return nil, fmt.Errorf("CV old-lock registry order/index mismatch")
		}
		publicShare, err := cvDecodeCanonicalG2(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid CV old-lock public share %d: %w", i+1, err)
		}
		material.publicShares[i] = publicShare
		transportPublicShare, err := cvDecodeCanonicalG1(entry.TransportPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid CV old-lock transport public share %d: %w", i+1, err)
		}
		var negPublicShare bls12381.G2Affine
		negPublicShare.Neg(&publicShare)
		pairingG1 = append(pairingG1, transportPublicShare, genG1)
		pairingG2 = append(pairingG2, genG2, negPublicShare)
		material.transportPublicShares[i] = transportPublicShare
		memberIndex[entry.MemberID] = i
	}
	if ok, pairingErr := bls12381.PairingCheck(pairingG1, pairingG2); pairingErr != nil || !ok {
		return nil, fmt.Errorf("CV old-lock transport keys do not match threshold public shares")
	}
	baseIndices := make([]int, threshold)
	basePoints := make([]bls12381.G2Affine, threshold)
	for i := 0; i < threshold; i++ {
		baseIndices[i] = i + 1
		basePoints[i] = material.publicShares[i]
	}
	constant, err := cvInterpolateG2At(baseIndices, basePoints, 0)
	if err != nil || !constant.Equal(&material.groupPublic) {
		return nil, fmt.Errorf("CV old-lock group key is inconsistent with public shares")
	}
	for i := threshold; i < len(material.publicShares); i++ {
		expected, err := cvInterpolateG2At(baseIndices, basePoints, i+1)
		if err != nil || !expected.Equal(&material.publicShares[i]) {
			return nil, fmt.Errorf("CV old-lock public shares are not a degree-%d polynomial", threshold-1)
		}
	}
	for _, member := range localMembers {
		index, ok := memberIndex[member]
		if !ok {
			return nil, fmt.Errorf("local old-lock member %d is outside registry", member)
		}
		encoded, err := cvReadReceiverSecret(cvOldLockSecretPath(secretDir, member))
		if err != nil {
			return nil, err
		}
		var secret fr.Element
		if err := secret.SetBytesCanonical(encoded); err != nil || secret.IsZero() {
			return nil, fmt.Errorf("invalid local old-lock secret for %d", member)
		}
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, secret.BigInt(new(big.Int)))
		if !publicShare.Equal(&material.publicShares[index]) {
			return nil, fmt.Errorf("local old-lock secret/public mismatch for %d", member)
		}
		var transportPublic bls12381.G1Affine
		transportPublic.ScalarMultiplication(&genG1, secret.BigInt(new(big.Int)))
		if !transportPublic.Equal(&material.transportPublicShares[index]) {
			return nil, fmt.Errorf("local old-lock transport secret/public mismatch for %d", member)
		}
		material.localShares[member] = secret
	}
	return material, nil
}

func cvDecodeCanonicalG1(encodedHex string) (bls12381.G1Affine, error) {
	encoded, err := hex.DecodeString(encodedHex)
	if err != nil || len(encoded) != bls12381.SizeOfG1AffineCompressed || hex.EncodeToString(encoded) != encodedHex {
		return bls12381.G1Affine{}, fmt.Errorf("invalid canonical G1 encoding")
	}
	var point bls12381.G1Affine
	consumed, err := point.SetBytes(encoded)
	if err != nil || consumed != len(encoded) || !cvValidG1(&point, false) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid G1 point")
	}
	return point, nil
}

func cvDecodeCanonicalG2(encodedHex string) (bls12381.G2Affine, error) {
	encoded, err := hex.DecodeString(encodedHex)
	if err != nil || len(encoded) != bls12381.SizeOfG2AffineCompressed || hex.EncodeToString(encoded) != encodedHex {
		return bls12381.G2Affine{}, fmt.Errorf("invalid canonical G2 encoding")
	}
	var point bls12381.G2Affine
	consumed, err := point.SetBytes(encoded)
	if err != nil || consumed != len(encoded) || !point.IsOnCurve() || !point.IsInSubGroup() || point.IsInfinity() {
		return bls12381.G2Affine{}, fmt.Errorf("invalid G2 point")
	}
	return point, nil
}

func cvInterpolateG2At(indices []int, points []bls12381.G2Affine, target int) (bls12381.G2Affine, error) {
	if len(indices) == 0 || len(indices) != len(points) {
		return bls12381.G2Affine{}, fmt.Errorf("invalid G2 interpolation input")
	}
	var result bls12381.G2Affine
	result.ScalarMultiplication(&genG2, big.NewInt(0))
	for i, xI := range indices {
		var coefficient fr.Element
		coefficient.SetOne()
		for j, xJ := range indices {
			if i == j {
				continue
			}
			var numerator, denominator fr.Element
			numerator.SetInt64(int64(target - xJ))
			denominator.SetInt64(int64(xI - xJ))
			if denominator.IsZero() {
				return bls12381.G2Affine{}, fmt.Errorf("duplicate G2 interpolation index")
			}
			denominator.Inverse(&denominator)
			numerator.Mul(&numerator, &denominator)
			coefficient.Mul(&coefficient, &numerator)
		}
		var term bls12381.G2Affine
		term.ScalarMultiplication(&points[i], coefficient.BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result, nil
}
