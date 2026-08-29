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
	cvOldCommitteeKeyBundleScalarVersion  = 2
	cvOldCommitteeKeyBundleScalarFilename = "old-committee-key-bundle-v2.json"
	cvScalarRoleAPDB                      = "apdb"
	cvScalarRoleControl                   = "control"
	cvScalarRoleCoin                      = "coin"
)

type cvScalarThresholdRegistryMember struct {
	MemberID           int    `json:"member_id"`
	ShareIndex         int    `json:"share_index"`
	PublicKey          string `json:"public_key"`
	TransportPublicKey string `json:"transport_public_key"`
}

type cvScalarThresholdRoleRegistry struct {
	Role           string                            `json:"role"`
	Threshold      int                               `json:"threshold"`
	GroupPublicKey string                            `json:"group_public_key"`
	Members        []cvScalarThresholdRegistryMember `json:"members"`
}

type cvOldCommitteeKeyBundleScalarRegistry struct {
	Version int                             `json:"version"`
	SID     string                          `json:"sid"`
	Epoch   uint64                          `json:"epoch"`
	Roles   []cvScalarThresholdRoleRegistry `json:"roles"`
}

type cvScalarThresholdKeyMaterial struct {
	role                  string
	members               []int
	threshold             int
	groupPublic           bls12381.G2Affine
	publicShares          []bls12381.G2Affine
	transportPublicShares []bls12381.G1Affine
	localShares           map[int]fr.Element
}

type cvOldCommitteeKeyBundleScalar struct {
	apdb    *cvScalarThresholdKeyMaterial
	control *cvScalarThresholdKeyMaterial
	coin    *cvScalarThresholdKeyMaterial
}

func cvScalarThresholdSecretPath(dir, role string, member int) string {
	return filepath.Join(dir, fmt.Sprintf("old-node-%d-v2-%s.scalar", member, role))
}

func cvGenerateOldCommitteeKeyBundleScalar(
	publicDir, secretDir, sid string, epoch uint64, members []int, params cvScalarParams,
) error {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 || len(members) == 0 {
		return fmt.Errorf("invalid CV V2 old-committee key bundle generation parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return err
	}
	if err := cvValidateDistinctReceiverIDs(members, false); err != nil {
		return err
	}
	if !equalInts(sortedCopy(members), members) {
		return fmt.Errorf("CV V2 old-committee key bundle requires canonical member order")
	}
	roles := []struct {
		name      string
		threshold int
	}{
		{cvScalarRoleAPDB, params.apdbLockThreshold},
		{cvScalarRoleControl, params.decisionThreshold},
		{cvScalarRoleCoin, params.componentCount},
	}
	for _, role := range roles {
		if role.threshold <= 0 || role.threshold > len(members) {
			return fmt.Errorf("invalid CV V2 %s key threshold", role.name)
		}
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
	paths := []string{filepath.Join(publicDir, cvOldCommitteeKeyBundleScalarFilename)}
	for _, role := range roles {
		for _, member := range members {
			paths = append(paths, cvScalarThresholdSecretPath(secretDir, role.name, member))
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV V2 old-committee key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	registry := cvOldCommitteeKeyBundleScalarRegistry{
		Version: cvOldCommitteeKeyBundleScalarVersion, SID: sid, Epoch: epoch,
		Roles: make([]cvScalarThresholdRoleRegistry, len(roles)),
	}
	roleShares := make([][]fr.Element, len(roles))
	seenGroupKeys := make(map[[bls12381.SizeOfG2AffineCompressed]byte]struct{}, len(roles))
	for i, role := range roles {
		for {
			shares, roleRegistry, err := cvGenerateScalarThresholdRole(role.name, members, role.threshold)
			if err != nil {
				return err
			}
			group, decodeErr := cvDecodeCanonicalG2(roleRegistry.GroupPublicKey)
			if decodeErr != nil {
				return decodeErr
			}
			encoded := group.Bytes()
			if _, duplicate := seenGroupKeys[encoded]; duplicate {
				continue
			}
			seenGroupKeys[encoded] = struct{}{}
			roleShares[i], registry.Roles[i] = shares, roleRegistry
			break
		}
	}
	if _, err := cvValidateOldCommitteeKeyBundleScalar(&registry, members, roles); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	created := make([]string, 0, len(paths))
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for roleIndex, role := range roles {
		for memberIndex, member := range members {
			encoded := roleShares[roleIndex][memberIndex].Bytes()
			path := cvScalarThresholdSecretPath(secretDir, role.name, member)
			if err := cvWriteExclusiveKeyFile(path, encoded[:], 0o600); err != nil {
				cleanup()
				return err
			}
			created = append(created, path)
		}
	}
	if err := cvWriteExclusiveKeyFile(filepath.Join(publicDir, cvOldCommitteeKeyBundleScalarFilename), raw, 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func cvGenerateScalarThresholdRole(role string, members []int, threshold int) ([]fr.Element, cvScalarThresholdRoleRegistry, error) {
	if !cvScalarKnownThresholdRole(role) || threshold <= 0 || threshold > len(members) {
		return nil, cvScalarThresholdRoleRegistry{}, fmt.Errorf("invalid CV V2 threshold role")
	}
	var coefficients, shares []fr.Element
	for {
		coefficients = make([]fr.Element, threshold)
		for i := range coefficients {
			if _, err := coefficients[i].SetRandom(); err != nil {
				return nil, cvScalarThresholdRoleRegistry{}, err
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
	var group bls12381.G2Affine
	group.ScalarMultiplication(&genG2, coefficients[0].BigInt(new(big.Int)))
	groupBytes := group.Bytes()
	registry := cvScalarThresholdRoleRegistry{
		Role: role, Threshold: threshold, GroupPublicKey: hex.EncodeToString(groupBytes[:]),
		Members: make([]cvScalarThresholdRegistryMember, len(members)),
	}
	for i, member := range members {
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, shares[i].BigInt(new(big.Int)))
		publicBytes := publicShare.Bytes()
		var transportShare bls12381.G1Affine
		transportShare.ScalarMultiplication(&genG1, shares[i].BigInt(new(big.Int)))
		transportBytes := transportShare.Bytes()
		registry.Members[i] = cvScalarThresholdRegistryMember{
			MemberID: member, ShareIndex: i + 1, PublicKey: hex.EncodeToString(publicBytes[:]),
			TransportPublicKey: hex.EncodeToString(transportBytes[:]),
		}
	}
	return shares, registry, nil
}

func cvLoadOldCommitteeKeyBundleScalar(
	publicDir, secretDir, sid string, epoch uint64, members, localMembers []int, params cvScalarParams,
) (*cvOldCommitteeKeyBundleScalar, error) {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 {
		return nil, fmt.Errorf("invalid CV V2 old-committee key bundle loading parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(members, false); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(localMembers, false); err != nil {
		return nil, err
	}
	if !equalInts(sortedCopy(members), members) {
		return nil, fmt.Errorf("CV V2 old-committee key bundle requires canonical member order")
	}
	raw, err := cvReadBoundedRegularFile(filepath.Join(publicDir, cvOldCommitteeKeyBundleScalarFilename), cvMaxReceiverRegistryBytes)
	if err != nil {
		return nil, err
	}
	var registry cvOldCommitteeKeyBundleScalarRegistry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV V2 old-committee key bundle suffix")
	}
	canonical, err := json.MarshalIndent(registry, "", "  ")
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return nil, fmt.Errorf("non-canonical CV V2 old-committee key bundle")
	}
	if registry.Version != cvOldCommitteeKeyBundleScalarVersion || registry.SID != sid || registry.Epoch != epoch {
		return nil, fmt.Errorf("CV V2 old-committee key bundle context mismatch")
	}
	roles := []struct {
		name      string
		threshold int
	}{
		{cvScalarRoleAPDB, params.apdbLockThreshold},
		{cvScalarRoleControl, params.decisionThreshold},
		{cvScalarRoleCoin, params.componentCount},
	}
	validated, err := cvValidateOldCommitteeKeyBundleScalar(&registry, members, roles)
	if err != nil {
		return nil, err
	}
	bundle := &cvOldCommitteeKeyBundleScalar{}
	for i, role := range roles {
		material, loadErr := cvLoadScalarThresholdRole(validated[i], members, localMembers, secretDir)
		if loadErr != nil {
			return nil, loadErr
		}
		switch role.name {
		case cvScalarRoleAPDB:
			bundle.apdb = material
		case cvScalarRoleControl:
			bundle.control = material
		case cvScalarRoleCoin:
			bundle.coin = material
		}
	}
	if bundle.apdb == nil || bundle.control == nil || bundle.coin == nil {
		return nil, fmt.Errorf("incomplete CV V2 old-committee key bundle")
	}
	return bundle, nil
}

func cvValidateOldCommitteeKeyBundleScalar(
	registry *cvOldCommitteeKeyBundleScalarRegistry, members []int,
	expected []struct {
		name      string
		threshold int
	},
) ([]cvScalarThresholdRoleRegistry, error) {
	if registry == nil || len(registry.Roles) != len(expected) {
		return nil, fmt.Errorf("invalid CV V2 old-committee key role count")
	}
	validated := make([]cvScalarThresholdRoleRegistry, len(expected))
	seenGroupKeys := make(map[[bls12381.SizeOfG2AffineCompressed]byte]struct{}, len(expected))
	for i, expectedRole := range expected {
		role := registry.Roles[i]
		if role.Role != expectedRole.name || role.Threshold != expectedRole.threshold || len(role.Members) != len(members) {
			return nil, fmt.Errorf("CV V2 threshold role context mismatch")
		}
		group, err := cvDecodeCanonicalG2(role.GroupPublicKey)
		if err != nil {
			return nil, err
		}
		encodedGroup := group.Bytes()
		if _, duplicate := seenGroupKeys[encodedGroup]; duplicate {
			return nil, fmt.Errorf("CV V2 threshold roles reuse a group key")
		}
		seenGroupKeys[encodedGroup] = struct{}{}
		publicShares := make([]bls12381.G2Affine, len(members))
		pairingG1 := make([]bls12381.G1Affine, 0, 2*len(members))
		pairingG2 := make([]bls12381.G2Affine, 0, 2*len(members))
		for memberIndex, entry := range role.Members {
			if entry.MemberID != members[memberIndex] || entry.ShareIndex != memberIndex+1 {
				return nil, fmt.Errorf("CV V2 threshold role member order mismatch")
			}
			publicShare, decodeErr := cvDecodeCanonicalG2(entry.PublicKey)
			if decodeErr != nil {
				return nil, decodeErr
			}
			transportShare, decodeErr := cvDecodeCanonicalG1(entry.TransportPublicKey)
			if decodeErr != nil {
				return nil, decodeErr
			}
			var negative bls12381.G2Affine
			negative.Neg(&publicShare)
			pairingG1 = append(pairingG1, transportShare, genG1)
			pairingG2 = append(pairingG2, genG2, negative)
			publicShares[memberIndex] = publicShare
		}
		if ok, pairingErr := bls12381.PairingCheck(pairingG1, pairingG2); pairingErr != nil || !ok {
			return nil, fmt.Errorf("CV V2 threshold transport keys do not match public shares")
		}
		baseIndices := make([]int, expectedRole.threshold)
		basePoints := make([]bls12381.G2Affine, expectedRole.threshold)
		for pointIndex := range basePoints {
			baseIndices[pointIndex] = pointIndex + 1
			basePoints[pointIndex] = publicShares[pointIndex]
		}
		constant, interpolateErr := cvInterpolateG2At(baseIndices, basePoints, 0)
		if interpolateErr != nil || !constant.Equal(&group) {
			return nil, fmt.Errorf("CV V2 threshold role group key is inconsistent with public shares")
		}
		for pointIndex := expectedRole.threshold; pointIndex < len(publicShares); pointIndex++ {
			expectedShare, interpolateErr := cvInterpolateG2At(baseIndices, basePoints, pointIndex+1)
			if interpolateErr != nil || !expectedShare.Equal(&publicShares[pointIndex]) {
				return nil, fmt.Errorf("CV V2 threshold public shares are not a degree-%d polynomial", expectedRole.threshold-1)
			}
		}
		validated[i] = role
	}
	return validated, nil
}

func cvLoadScalarThresholdRole(
	role cvScalarThresholdRoleRegistry, members, localMembers []int, secretDir string,
) (*cvScalarThresholdKeyMaterial, error) {
	group, err := cvDecodeCanonicalG2(role.GroupPublicKey)
	if err != nil {
		return nil, err
	}
	material := &cvScalarThresholdKeyMaterial{
		role: role.Role, members: append([]int(nil), members...), threshold: role.Threshold, groupPublic: group,
		publicShares: make([]bls12381.G2Affine, len(members)), transportPublicShares: make([]bls12381.G1Affine, len(members)),
		localShares: make(map[int]fr.Element, len(localMembers)),
	}
	memberIndex := make(map[int]int, len(members))
	for i, entry := range role.Members {
		publicShare, decodeErr := cvDecodeCanonicalG2(entry.PublicKey)
		if decodeErr != nil {
			return nil, decodeErr
		}
		transportShare, decodeErr := cvDecodeCanonicalG1(entry.TransportPublicKey)
		if decodeErr != nil {
			return nil, decodeErr
		}
		material.publicShares[i] = publicShare
		material.transportPublicShares[i] = transportShare
		memberIndex[entry.MemberID] = i
	}
	for _, member := range localMembers {
		index, ok := memberIndex[member]
		if !ok {
			return nil, fmt.Errorf("local CV V2 threshold member is outside registry")
		}
		raw, readErr := cvReadReceiverSecret(cvScalarThresholdSecretPath(secretDir, role.Role, member))
		if readErr != nil {
			return nil, readErr
		}
		var share fr.Element
		if err := share.SetBytesCanonical(raw); err != nil || share.IsZero() {
			return nil, fmt.Errorf("invalid local CV V2 threshold share")
		}
		var publicShare bls12381.G2Affine
		publicShare.ScalarMultiplication(&genG2, share.BigInt(new(big.Int)))
		if !publicShare.Equal(&material.publicShares[index]) {
			return nil, fmt.Errorf("local CV V2 threshold share/public mismatch")
		}
		material.localShares[member] = share
	}
	return material, nil
}

func cvScalarKnownThresholdRole(role string) bool {
	return role == cvScalarRoleAPDB || role == cvScalarRoleControl || role == cvScalarRoleCoin
}
