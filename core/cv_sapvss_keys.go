package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvReceiverRegistryVersion        = 2
	cvReceiverRegistryFilename       = "registry.json"
	cvMaxReceiverRegistryBytes       = 1 << 20
	cvReceiverIDRegistryDigestDomain = "ARL-CV-sAPVSS/receiver-id-registry"
)

type cvReceiverRegistryEntry struct {
	ReceiverID       int    `json:"receiver_id"`
	ReceiverIndex    int    `json:"receiver_index"`
	PublicKey        string `json:"public_key"`
	SigningPublicKey string `json:"signing_public_key"`
}

type cvReceiverRegistry struct {
	Version   int                       `json:"version"`
	SID       string                    `json:"sid"`
	Receivers []cvReceiverRegistryEntry `json:"receivers"`
}

type cvReceiverKeyMaterial struct {
	receiverOrder               []int
	receiverIndex               map[int]int
	receiverPublicKeys          []bls12381.G1Affine
	receiverSigningPublicKeys   []bls12381.G1Affine
	localReceiverSecrets        map[int]fr.Element
	localReceiverSigningSecrets map[int]fr.Element
	registryDigest              []byte
}

func GenerateCVReceiverKeyMaterial(publicDir, secretDir, sid string, receiverIDs []int) error {
	return cvGenerateReceiverKeyMaterial(publicDir, secretDir, sid, receiverIDs)
}

func cvReceiverSecretPath(dir string, receiverID int) string {
	return filepath.Join(dir, fmt.Sprintf("receiver-%d.scalar", receiverID))
}

func cvReceiverSigningSecretPath(dir string, receiverID int) string {
	return filepath.Join(dir, fmt.Sprintf("receiver-%d-signing.scalar", receiverID))
}

func cvGenerateReceiverKeyMaterial(publicDir, localSecretDir, sid string, receiverIDs []int) error {
	if publicDir == "" || localSecretDir == "" || sid == "" || len(receiverIDs) == 0 {
		return fmt.Errorf("invalid CV-sAPVSS receiver key generation parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, localSecretDir); err != nil {
		return err
	}
	if err := cvValidateDistinctReceiverIDs(receiverIDs, false); err != nil {
		return err
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return fmt.Errorf("create CV-sAPVSS public key directory: %w", err)
	}
	if err := os.MkdirAll(localSecretDir, 0o700); err != nil {
		return fmt.Errorf("create CV-sAPVSS secret key directory: %w", err)
	}
	if err := os.Chmod(localSecretDir, 0o700); err != nil {
		return fmt.Errorf("secure CV-sAPVSS secret key directory: %w", err)
	}

	paths := make([]string, 0, 2*len(receiverIDs)+1)
	paths = append(paths, filepath.Join(publicDir, cvReceiverRegistryFilename))
	for _, id := range receiverIDs {
		paths = append(paths, cvReceiverSecretPath(localSecretDir, id))
		paths = append(paths, cvReceiverSigningSecretPath(localSecretDir, id))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV-sAPVSS key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect CV-sAPVSS key file %s: %w", path, err)
		}
	}

	registry := cvReceiverRegistry{
		Version:   cvReceiverRegistryVersion,
		SID:       sid,
		Receivers: make([]cvReceiverRegistryEntry, len(receiverIDs)),
	}
	secretBytes := make([][]byte, len(receiverIDs))
	signingSecretBytes := make([][]byte, len(receiverIDs))
	seenKeys := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, 2*len(receiverIDs))
	for i, id := range receiverIDs {
		for {
			secret, err := cvRandomReceiverSecret()
			if err != nil {
				return err
			}
			publicKey, err := cvReceiverPublicKey(secret)
			if err != nil {
				return err
			}
			encodedKey := publicKey.Bytes()
			if _, duplicate := seenKeys[encodedKey]; duplicate {
				continue
			}
			signingSecret, err := cvRandomReceiverSecret()
			if err != nil {
				return err
			}
			if signingSecret.Equal(&secret) {
				continue
			}
			signingPublicKey, err := cvReceiverPublicKey(signingSecret)
			if err != nil {
				return err
			}
			encodedSigningKey := signingPublicKey.Bytes()
			if _, duplicate := seenKeys[encodedSigningKey]; duplicate {
				continue
			}
			seenKeys[encodedKey] = struct{}{}
			seenKeys[encodedSigningKey] = struct{}{}
			encodedSecret := secret.Bytes()
			secretBytes[i] = append([]byte(nil), encodedSecret[:]...)
			encodedSigningSecret := signingSecret.Bytes()
			signingSecretBytes[i] = append([]byte(nil), encodedSigningSecret[:]...)
			registry.Receivers[i] = cvReceiverRegistryEntry{
				ReceiverID:       id,
				ReceiverIndex:    i + 1,
				PublicKey:        hex.EncodeToString(encodedKey[:]),
				SigningPublicKey: hex.EncodeToString(encodedSigningKey[:]),
			}
			break
		}
	}

	registryRaw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("encode CV-sAPVSS receiver registry: %w", err)
	}
	registryRaw = append(registryRaw, '\n')
	created := make([]string, 0, len(receiverIDs))
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for i, id := range receiverIDs {
		path := cvReceiverSecretPath(localSecretDir, id)
		if err := cvWriteExclusiveKeyFile(path, secretBytes[i], 0o600); err != nil {
			cleanup()
			return fmt.Errorf("write CV-sAPVSS receiver secret %d: %w", id, err)
		}
		created = append(created, path)
		signingPath := cvReceiverSigningSecretPath(localSecretDir, id)
		if err := cvWriteExclusiveKeyFile(signingPath, signingSecretBytes[i], 0o600); err != nil {
			cleanup()
			return fmt.Errorf("write CV-sAPVSS receiver signing secret %d: %w", id, err)
		}
		created = append(created, signingPath)
	}
	registryPath := filepath.Join(publicDir, cvReceiverRegistryFilename)
	if err := cvWriteExclusiveKeyFile(registryPath, registryRaw, 0o644); err != nil {
		cleanup()
		return fmt.Errorf("write CV-sAPVSS receiver registry: %w", err)
	}
	return nil
}

func cvLoadReceiverKeyMaterial(
	publicDir, localSecretDir, sid string,
	expectedReceiverIDs, localReceiverIDs []int,
) (*cvReceiverKeyMaterial, error) {
	if publicDir == "" || localSecretDir == "" || sid == "" || len(expectedReceiverIDs) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver key loading parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, localSecretDir); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(expectedReceiverIDs, false); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(localReceiverIDs, true); err != nil {
		return nil, err
	}

	raw, err := cvReadBoundedRegularFile(
		filepath.Join(publicDir, cvReceiverRegistryFilename),
		cvMaxReceiverRegistryBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read CV-sAPVSS receiver registry: %w", err)
	}
	var registry cvReceiverRegistry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS receiver registry: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver registry suffix")
	}
	if registry.Version != cvReceiverRegistryVersion {
		return nil, fmt.Errorf("unsupported CV-sAPVSS receiver registry version: %d", registry.Version)
	}
	if registry.SID != sid {
		return nil, fmt.Errorf("CV-sAPVSS receiver registry SID mismatch")
	}
	if len(registry.Receivers) != len(expectedReceiverIDs) {
		return nil, fmt.Errorf("CV-sAPVSS receiver registry count mismatch")
	}

	material := &cvReceiverKeyMaterial{
		receiverOrder:               append([]int(nil), expectedReceiverIDs...),
		receiverIndex:               make(map[int]int, len(expectedReceiverIDs)),
		receiverPublicKeys:          make([]bls12381.G1Affine, len(expectedReceiverIDs)),
		receiverSigningPublicKeys:   make([]bls12381.G1Affine, len(expectedReceiverIDs)),
		localReceiverSecrets:        make(map[int]fr.Element, len(localReceiverIDs)),
		localReceiverSigningSecrets: make(map[int]fr.Element, len(localReceiverIDs)),
	}
	seenKeys := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, 2*len(expectedReceiverIDs))
	for i, entry := range registry.Receivers {
		if entry.ReceiverID != expectedReceiverIDs[i] || entry.ReceiverIndex != i+1 {
			return nil, fmt.Errorf("CV-sAPVSS receiver registry order/index mismatch at position %d", i+1)
		}
		encoded, err := hex.DecodeString(entry.PublicKey)
		if err != nil || len(encoded) != bls12381.SizeOfG1AffineCompressed ||
			hex.EncodeToString(encoded) != entry.PublicKey {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver public key encoding at index %d", i+1)
		}
		var publicKey bls12381.G1Affine
		consumed, err := publicKey.SetBytes(encoded)
		if err != nil || consumed != len(encoded) || !cvValidG1(&publicKey, false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver public key at index %d", i+1)
		}
		encodedKey := publicKey.Bytes()
		if _, duplicate := seenKeys[encodedKey]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS receiver public key at index %d", i+1)
		}
		seenKeys[encodedKey] = struct{}{}
		material.receiverIndex[entry.ReceiverID] = entry.ReceiverIndex
		material.receiverPublicKeys[i] = publicKey
		signingEncoded, err := hex.DecodeString(entry.SigningPublicKey)
		if err != nil || len(signingEncoded) != bls12381.SizeOfG1AffineCompressed ||
			hex.EncodeToString(signingEncoded) != entry.SigningPublicKey {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver signing public key encoding at index %d", i+1)
		}
		var signingPublicKey bls12381.G1Affine
		consumed, err = signingPublicKey.SetBytes(signingEncoded)
		if err != nil || consumed != len(signingEncoded) || !cvValidG1(&signingPublicKey, false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver signing public key at index %d", i+1)
		}
		encodedSigningKey := signingPublicKey.Bytes()
		if _, duplicate := seenKeys[encodedSigningKey]; duplicate {
			return nil, fmt.Errorf("CV-sAPVSS receiver signing key reuses a registry key at index %d", i+1)
		}
		seenKeys[encodedSigningKey] = struct{}{}
		material.receiverSigningPublicKeys[i] = signingPublicKey
	}
	material.registryDigest, err = cvIDBoundReceiverRegistryDigest(
		sid,
		material.receiverOrder,
		material.receiverPublicKeys,
		material.receiverSigningPublicKeys,
	)
	if err != nil {
		return nil, err
	}

	for _, id := range localReceiverIDs {
		index, ok := material.receiverIndex[id]
		if !ok {
			return nil, fmt.Errorf("local CV-sAPVSS receiver %d is outside the registry", id)
		}
		encoded, err := cvReadReceiverSecret(cvReceiverSecretPath(localSecretDir, id))
		if err != nil {
			return nil, fmt.Errorf("read local CV-sAPVSS receiver secret %d: %w", id, err)
		}
		if len(encoded) != fr.Bytes {
			return nil, fmt.Errorf("invalid local CV-sAPVSS receiver secret length for %d", id)
		}
		var secret fr.Element
		if err := secret.SetBytesCanonical(encoded); err != nil || secret.IsZero() {
			return nil, fmt.Errorf("invalid local CV-sAPVSS receiver secret for %d", id)
		}
		publicKey, err := cvReceiverPublicKey(secret)
		if err != nil || !publicKey.Equal(&material.receiverPublicKeys[index-1]) {
			return nil, fmt.Errorf("local CV-sAPVSS receiver secret/public key mismatch for %d", id)
		}
		material.localReceiverSecrets[id] = secret
		signingEncoded, err := cvReadReceiverSecret(cvReceiverSigningSecretPath(localSecretDir, id))
		if err != nil {
			return nil, fmt.Errorf("read local CV-sAPVSS receiver signing secret %d: %w", id, err)
		}
		if len(signingEncoded) != fr.Bytes {
			return nil, fmt.Errorf("invalid local CV-sAPVSS receiver signing secret length for %d", id)
		}
		var signingSecret fr.Element
		if err := signingSecret.SetBytesCanonical(signingEncoded); err != nil || signingSecret.IsZero() {
			return nil, fmt.Errorf("invalid local CV-sAPVSS receiver signing secret for %d", id)
		}
		if signingSecret.Equal(&secret) {
			return nil, fmt.Errorf("CV-sAPVSS receiver encryption and signing secrets must be independent for %d", id)
		}
		signingPublicKey, err := cvReceiverPublicKey(signingSecret)
		if err != nil || !signingPublicKey.Equal(&material.receiverSigningPublicKeys[index-1]) {
			return nil, fmt.Errorf("local CV-sAPVSS receiver signing secret/public key mismatch for %d", id)
		}
		material.localReceiverSigningSecrets[id] = signingSecret
	}
	return material, nil
}

func cvIDBoundReceiverRegistryDigest(
	sid string,
	receiverIDs []int,
	publicKeys []bls12381.G1Affine,
	signingPublicKeys []bls12381.G1Affine,
) ([]byte, error) {
	if sid == "" || len(receiverIDs) == 0 || len(receiverIDs) != len(publicKeys) || len(publicKeys) != len(signingPublicKeys) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver registry digest input")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(sid)); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(receiverIDs)); err != nil {
		return nil, err
	}
	for i, id := range receiverIDs {
		if !cvValidG1(&publicKeys[i], false) || !cvValidG1(&signingPublicKeys[i], false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver registry key at index %d", i+1)
		}
		var encodedID [8]byte
		binary.BigEndian.PutUint64(encodedID[:], uint64(int64(id)))
		_, _ = wire.Write(encodedID[:])
		if err := cvWriteUint32(&wire, i+1); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &publicKeys[i])
		cvWritePoint(&wire, &signingPublicKeys[i])
	}
	return hashBytes([]byte(cvReceiverIDRegistryDigestDomain), wire.Bytes()), nil
}

func cvRandomReceiverSecret() (fr.Element, error) {
	for {
		var encoded [fr.Bytes]byte
		if _, err := rand.Read(encoded[:]); err != nil {
			return fr.Element{}, fmt.Errorf("generate CV-sAPVSS receiver secret: %w", err)
		}
		var secret fr.Element
		if err := secret.SetBytesCanonical(encoded[:]); err == nil && !secret.IsZero() {
			return secret, nil
		}
	}
}

func cvValidateDistinctReceiverIDs(receiverIDs []int, allowEmpty bool) error {
	if !allowEmpty && len(receiverIDs) == 0 {
		return fmt.Errorf("empty CV-sAPVSS receiver roster")
	}
	seen := make(map[int]struct{}, len(receiverIDs))
	for _, id := range receiverIDs {
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("duplicate CV-sAPVSS receiver ID: %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func cvRequireSeparateKeyDirs(publicDir, localSecretDir string) error {
	publicAbs, err := filepath.Abs(publicDir)
	if err != nil {
		return fmt.Errorf("resolve CV-sAPVSS public key directory: %w", err)
	}
	secretAbs, err := filepath.Abs(localSecretDir)
	if err != nil {
		return fmt.Errorf("resolve CV-sAPVSS secret key directory: %w", err)
	}
	if publicAbs == secretAbs {
		return fmt.Errorf("CV-sAPVSS public and secret key directories must differ")
	}
	return nil
}

func cvReadBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	file, info, err := cvOpenRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if maximum <= 0 || info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("CV-sAPVSS file exceeds size bound: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size() || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("CV-sAPVSS file changed size while reading: %s", path)
	}
	return raw, nil
}

func cvReadReceiverSecret(path string) ([]byte, error) {
	file, info, err := cvOpenRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("CV-sAPVSS receiver secret must have mode 0600: %s", path)
	}
	if info.Size() != fr.Bytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver secret size: %s", path)
	}
	encoded := make([]byte, fr.Bytes)
	if _, err := io.ReadFull(file, encoded); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("CV-sAPVSS receiver secret changed size while reading: %s", path)
	}
	return encoded, nil
}

func cvOpenRegularFileNoFollow(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("CV-sAPVSS key path is not a regular file: %s", path)
	}
	return file, info, nil
}

func cvWriteExclusiveKeyFile(path string, data []byte, mode os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		return err
	}
	if n, writeErr := file.Write(data); writeErr != nil {
		return writeErr
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
