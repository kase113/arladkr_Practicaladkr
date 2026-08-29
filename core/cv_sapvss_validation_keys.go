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
	cvValidatorRegistryScalarVersion  = 2
	cvValidatorRegistryScalarFilename = "validator-registry-v2.json"
	cvValidatorRegistryScalarDomain   = "ARL-CV-sAPVSS/v2-scalar-group/validator-registry"
	cvValidatorPoPDomain              = "ARL-CV-sAPVSS/v2-scalar-group/validator-pop"
)

// cvValidatorRegistryEntryScalar contains a validator's independent BLS key. It
// is deliberately separate from all threshold roles in the old committee key
// bundle: a VCert is a sampled collection of individually accountable votes.
type cvValidatorRegistryEntryScalar struct {
	MemberID       int    `json:"member_id"`
	PublicKey      string `json:"public_key"`
	ProofOfPossess string `json:"proof_of_possession"`
}

type cvValidatorRegistryScalar struct {
	Version    int                              `json:"version"`
	SID        string                           `json:"sid"`
	Epoch      uint64                           `json:"epoch"`
	Validators []cvValidatorRegistryEntryScalar `json:"validators"`
}

type cvValidatorKeyMaterialScalar struct {
	memberOrder  []int
	memberIndex  map[int]int
	publicKeys   []bls12381.G2Affine
	localSecrets map[int]fr.Element
	registryHash []byte
	sid          string
	epoch        uint64
}

func cvValidatorScalarSecretPath(dir string, memberID int) string {
	return filepath.Join(dir, fmt.Sprintf("old-node-%d-validator.scalar", memberID))
}

func cvValidatorPoPStatementScalar(sid string, epoch uint64, memberID int, publicKey *bls12381.G2Affine) ([]byte, error) {
	if sid == "" || epoch == 0 || memberID < 0 || publicKey == nil || !cvValidG2(publicKey) {
		return nil, fmt.Errorf("invalid CV V2 validator PoP statement")
	}
	encoded := publicKey.Bytes()
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(sid))
	cvWriteUint64(&wire, epoch)
	cvWriteUint64(&wire, uint64(memberID))
	_ = cvWriteBytes(&wire, encoded[:])
	return hashBytes([]byte(cvValidatorPoPDomain), wire.Bytes()), nil
}

func cvSignValidatorScalar(secret fr.Element, domain string, digest []byte) ([]byte, error) {
	if secret.IsZero() || domain == "" || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 validator signing input")
	}
	hashPoint, err := bls12381.HashToG1(domainDigest(domain, digest), []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("hash CV V2 validator signature: %w", err)
	}
	var signature bls12381.G1Affine
	signature.ScalarMultiplication(&hashPoint, secret.BigInt(new(big.Int)))
	encoded := signature.Bytes()
	return append([]byte(nil), encoded[:]...), nil
}

func cvVerifyValidatorSignatureScalar(publicKey *bls12381.G2Affine, domain string, digest, signatureWire []byte) bool {
	if publicKey == nil || !cvValidG2(publicKey) || domain == "" || len(digest) != 32 ||
		len(signatureWire) != bls12381.SizeOfG1AffineCompressed {
		return false
	}
	var signature bls12381.G1Affine
	consumed, err := signature.SetBytes(signatureWire)
	if err != nil || consumed != len(signatureWire) || !cvValidG1(&signature, false) {
		return false
	}
	hashPoint, err := bls12381.HashToG1(domainDigest(domain, digest), []byte(domain))
	if err != nil {
		return false
	}
	var negative bls12381.G2Affine
	negative.Neg(publicKey)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{signature, hashPoint},
		[]bls12381.G2Affine{genG2, negative},
	)
	return err == nil && ok
}

func cvGenerateValidatorRegistryScalar(publicDir, secretDir, sid string, epoch uint64, members []int) error {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 || len(members) == 0 {
		return fmt.Errorf("invalid CV V2 validator registry generation parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return err
	}
	if err := cvValidateDistinctReceiverIDs(members, false); err != nil || !equalInts(members, sortedCopy(members)) {
		return fmt.Errorf("CV V2 validator registry requires canonical member order")
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
	paths := []string{filepath.Join(publicDir, cvValidatorRegistryScalarFilename)}
	for _, member := range members {
		paths = append(paths, cvValidatorScalarSecretPath(secretDir, member))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV V2 validator key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	registry := cvValidatorRegistryScalar{Version: cvValidatorRegistryScalarVersion, SID: sid, Epoch: epoch, Validators: make([]cvValidatorRegistryEntryScalar, len(members))}
	secrets := make([][]byte, len(members))
	seen := make(map[[bls12381.SizeOfG2AffineCompressed]byte]struct{}, len(members))
	for i, member := range members {
		var secret fr.Element
		var publicKey bls12381.G2Affine
		for {
			if _, err := secret.SetRandom(); err != nil {
				return fmt.Errorf("generate CV V2 validator secret: %w", err)
			}
			if secret.IsZero() {
				continue
			}
			publicKey.ScalarMultiplication(&genG2, secret.BigInt(new(big.Int)))
			encoded := publicKey.Bytes()
			if _, duplicate := seen[encoded]; !duplicate {
				seen[encoded] = struct{}{}
				break
			}
		}
		statement, err := cvValidatorPoPStatementScalar(sid, epoch, member, &publicKey)
		if err != nil {
			return err
		}
		proof, err := cvSignValidatorScalar(secret, cvValidatorPoPDomain, statement)
		if err != nil {
			return err
		}
		publicEncoded := publicKey.Bytes()
		secretEncoded := secret.Bytes()
		registry.Validators[i] = cvValidatorRegistryEntryScalar{
			MemberID: member, PublicKey: hex.EncodeToString(publicEncoded[:]), ProofOfPossess: hex.EncodeToString(proof),
		}
		secrets[i] = append([]byte(nil), secretEncoded[:]...)
	}
	if _, err := cvValidatorRegistryScalarDigest(&registry); err != nil {
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
	for i, member := range members {
		path := cvValidatorScalarSecretPath(secretDir, member)
		if err := cvWriteExclusiveKeyFile(path, secrets[i], 0o600); err != nil {
			cleanup()
			return err
		}
		created = append(created, path)
	}
	if err := cvWriteExclusiveKeyFile(filepath.Join(publicDir, cvValidatorRegistryScalarFilename), raw, 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func cvValidatorRegistryScalarDigest(registry *cvValidatorRegistryScalar) ([]byte, error) {
	if registry == nil || registry.Version != cvValidatorRegistryScalarVersion || registry.SID == "" || registry.Epoch == 0 || len(registry.Validators) == 0 {
		return nil, fmt.Errorf("invalid CV V2 validator registry")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(registry.SID))
	cvWriteUint64(&wire, registry.Epoch)
	if err := cvWriteUint32(&wire, len(registry.Validators)); err != nil {
		return nil, err
	}
	for _, entry := range registry.Validators {
		if entry.MemberID < 0 {
			return nil, fmt.Errorf("invalid CV V2 validator registry member")
		}
		publicKey, err := cvDecodeCanonicalG2(entry.PublicKey)
		if err != nil {
			return nil, err
		}
		proof, err := hex.DecodeString(entry.ProofOfPossess)
		if err != nil || hex.EncodeToString(proof) != entry.ProofOfPossess || len(proof) != bls12381.SizeOfG1AffineCompressed {
			return nil, fmt.Errorf("invalid CV V2 validator PoP encoding")
		}
		encoded := publicKey.Bytes()
		cvWriteUint64(&wire, uint64(entry.MemberID))
		_ = cvWriteBytes(&wire, encoded[:])
		_ = cvWriteBytes(&wire, proof)
	}
	return hashBytes([]byte(cvValidatorRegistryScalarDomain), wire.Bytes()), nil
}

func cvLoadValidatorRegistryScalar(publicDir, secretDir, sid string, epoch uint64, expectedMembers, localMembers []int) (*cvValidatorKeyMaterialScalar, error) {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 || len(expectedMembers) == 0 {
		return nil, fmt.Errorf("invalid CV V2 validator registry loading parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(expectedMembers, false); err != nil || !equalInts(expectedMembers, sortedCopy(expectedMembers)) {
		return nil, fmt.Errorf("CV V2 validator registry requires canonical member order")
	}
	if err := cvValidateDistinctReceiverIDs(localMembers, true); err != nil {
		return nil, err
	}
	raw, err := cvReadBoundedRegularFile(filepath.Join(publicDir, cvValidatorRegistryScalarFilename), cvMaxReceiverRegistryScalarBytes)
	if err != nil {
		return nil, err
	}
	var registry cvValidatorRegistryScalar
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV V2 validator registry suffix")
	}
	canonical, err := json.MarshalIndent(registry, "", "  ")
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return nil, fmt.Errorf("non-canonical CV V2 validator registry")
	}
	if registry.Version != cvValidatorRegistryScalarVersion || registry.SID != sid || registry.Epoch != epoch || len(registry.Validators) != len(expectedMembers) {
		return nil, fmt.Errorf("CV V2 validator registry context mismatch")
	}
	material := &cvValidatorKeyMaterialScalar{
		memberOrder: append([]int(nil), expectedMembers...), memberIndex: make(map[int]int, len(expectedMembers)),
		publicKeys: make([]bls12381.G2Affine, len(expectedMembers)), localSecrets: make(map[int]fr.Element, len(localMembers)), sid: sid, epoch: epoch,
	}
	seen := make(map[[bls12381.SizeOfG2AffineCompressed]byte]struct{}, len(expectedMembers))
	for i, entry := range registry.Validators {
		if entry.MemberID != expectedMembers[i] {
			return nil, fmt.Errorf("CV V2 validator registry member order mismatch")
		}
		publicKey, err := cvDecodeCanonicalG2(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 validator public key: %w", err)
		}
		proof, err := hex.DecodeString(entry.ProofOfPossess)
		if err != nil || hex.EncodeToString(proof) != entry.ProofOfPossess {
			return nil, fmt.Errorf("invalid CV V2 validator PoP encoding")
		}
		statement, err := cvValidatorPoPStatementScalar(sid, epoch, entry.MemberID, &publicKey)
		if err != nil || !cvVerifyValidatorSignatureScalar(&publicKey, cvValidatorPoPDomain, statement, proof) {
			return nil, fmt.Errorf("invalid CV V2 validator proof of possession")
		}
		encoded := publicKey.Bytes()
		if _, duplicate := seen[encoded]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 validator public key")
		}
		seen[encoded] = struct{}{}
		material.memberIndex[entry.MemberID] = i
		material.publicKeys[i] = publicKey
	}
	material.registryHash, err = cvValidatorRegistryScalarDigest(&registry)
	if err != nil {
		return nil, err
	}
	for _, member := range localMembers {
		index, ok := material.memberIndex[member]
		if !ok {
			return nil, fmt.Errorf("local CV V2 validator is outside registry")
		}
		rawSecret, readErr := cvReadReceiverSecret(cvValidatorScalarSecretPath(secretDir, member))
		if readErr != nil {
			return nil, readErr
		}
		var secret fr.Element
		if err := secret.SetBytesCanonical(rawSecret); err != nil || secret.IsZero() {
			return nil, fmt.Errorf("invalid local CV V2 validator secret")
		}
		var publicKey bls12381.G2Affine
		publicKey.ScalarMultiplication(&genG2, secret.BigInt(new(big.Int)))
		if !publicKey.Equal(&material.publicKeys[index]) {
			return nil, fmt.Errorf("local CV V2 validator secret/public mismatch")
		}
		material.localSecrets[member] = secret
	}
	return material, nil
}

func cvValidG2(point *bls12381.G2Affine) bool {
	return point != nil && point.IsOnCurve() && point.IsInSubGroup() && !point.IsInfinity()
}
