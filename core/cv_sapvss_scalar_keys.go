package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvReceiverRegistryScalarVersion   = 2
	cvReceiverRegistryScalarFilename  = "receiver-registry-v2.json"
	cvReceiverRegistryScalarDomain    = "ARL-CV-sAPVSS/receiver-registry-v2"
	cvReceiverRegistryScalarPoKDomain = "ARL-CV-sAPVSS/receiver-encryption-pok-v2"
	cvMaxReceiverRegistryScalarBytes  = 1 << 20
)

type cvReceiverRegistryEntryScalar struct {
	ReceiverID         int    `json:"receiver_id"`
	ReceiverIndex      int    `json:"receiver_index"`
	EncryptionPublic   string `json:"encryption_public_key"`
	EncryptionKeyProof string `json:"encryption_key_proof"`
	IdentityPublic     string `json:"identity_public_key"`
}

type cvReceiverRegistryScalar struct {
	Version   int                             `json:"version"`
	SID       string                          `json:"sid"`
	Epoch     uint64                          `json:"epoch"`
	Receivers []cvReceiverRegistryEntryScalar `json:"receivers"`
}

type cvReceiverKeyMaterialScalar struct {
	receiverOrder          []int
	receiverIndex          map[int]int
	encryptionPublicKeys   []bls12381.G1Affine
	identityPublicKeys     []ed25519.PublicKey
	localEncryptionSecrets map[int]fr.Element
	localIdentitySecrets   map[int]ed25519.PrivateKey
	registryDigest         []byte
	sid                    string
	epoch                  uint64
}

func cvReceiverScalarEncryptionSecretPath(dir string, receiverID int) string {
	return filepath.Join(dir, fmt.Sprintf("receiver-%d-elgamal.scalar", receiverID))
}

func cvReceiverScalarIdentitySecretPath(dir string, receiverID int) string {
	return filepath.Join(dir, fmt.Sprintf("receiver-%d-identity.ed25519", receiverID))
}

func cvScalarReceiverPoKWire(commitment *bls12381.G1Affine, response *fr.Element) ([]byte, error) {
	if commitment == nil || !cvValidG1(commitment, false) || response == nil {
		return nil, fmt.Errorf("invalid CV V2 receiver encryption PoK")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvReceiverRegistryScalarPoKDomain))
	cvWritePoint(&wire, commitment)
	cvWriteScalar(&wire, response)
	return wire.Bytes(), nil
}

func cvScalarReceiverPoKChallenge(
	sid string, epoch uint64, receiverID, receiverIndex int,
	publicKey, commitment *bls12381.G1Affine,
) (fr.Element, error) {
	if sid == "" || receiverID < 0 || receiverIndex <= 0 ||
		!cvValidG1(publicKey, false) || !cvValidG1(commitment, false) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 receiver encryption PoK statement")
	}
	var statement bytes.Buffer
	_ = cvWriteBytes(&statement, []byte(sid))
	cvWriteUint64(&statement, epoch)
	cvWriteUint64(&statement, uint64(receiverID))
	cvWriteUint64(&statement, uint64(receiverIndex))
	cvWritePoint(&statement, publicKey)
	cvWritePoint(&statement, commitment)
	return cvHashToFr(cvReceiverRegistryScalarPoKDomain, statement.Bytes())
}

func cvProveReceiverEncryptionKeyScalar(
	sid string, epoch uint64, receiverID, receiverIndex int,
	secret fr.Element, publicKey *bls12381.G1Affine,
) ([]byte, error) {
	if secret.IsZero() || !cvValidG1(publicKey, false) {
		return nil, fmt.Errorf("invalid CV V2 receiver encryption key witness")
	}
	var nonce fr.Element
	for {
		if _, err := nonce.SetRandom(); err != nil {
			return nil, fmt.Errorf("sample CV V2 receiver encryption PoK nonce: %w", err)
		}
		if !nonce.IsZero() {
			break
		}
	}
	commitment := cvPointTimes(&genG1, &nonce)
	challenge, err := cvScalarReceiverPoKChallenge(sid, epoch, receiverID, receiverIndex, publicKey, &commitment)
	if err != nil {
		return nil, err
	}
	var response fr.Element
	response.Mul(&challenge, &secret).Add(&response, &nonce)
	return cvScalarReceiverPoKWire(&commitment, &response)
}

func cvVerifyReceiverEncryptionKeyScalar(
	sid string, epoch uint64, receiverID, receiverIndex int,
	publicKey *bls12381.G1Affine, proofWire []byte,
) error {
	if !cvValidG1(publicKey, false) || len(proofWire) == 0 {
		return fmt.Errorf("invalid CV V2 receiver encryption PoK input")
	}
	r := newCVWireReader(proofWire)
	domain, err := r.bytes(len(cvReceiverRegistryScalarPoKDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiverRegistryScalarPoKDomain)) {
		return fmt.Errorf("invalid CV V2 receiver encryption PoK domain")
	}
	commitment, err := r.point()
	if err != nil || !cvValidG1(&commitment, false) {
		return fmt.Errorf("invalid CV V2 receiver encryption PoK commitment")
	}
	response, err := r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return fmt.Errorf("invalid CV V2 receiver encryption PoK response")
	}
	canonical, err := cvScalarReceiverPoKWire(&commitment, &response)
	if err != nil || !bytes.Equal(canonical, proofWire) {
		return fmt.Errorf("non-canonical CV V2 receiver encryption PoK")
	}
	challenge, err := cvScalarReceiverPoKChallenge(sid, epoch, receiverID, receiverIndex, publicKey, &commitment)
	if err != nil {
		return err
	}
	lhs := cvPointTimes(&genG1, &response)
	rhs := cvPointSum(&commitment, pointPtr(cvPointTimes(publicKey, &challenge)))
	if !lhs.Equal(&rhs) {
		return fmt.Errorf("invalid CV V2 receiver encryption PoK equation")
	}
	return nil
}

func cvGenerateReceiverRegistryScalar(publicDir, secretDir, sid string, epoch uint64, receiverIDs []int) error {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 || len(receiverIDs) == 0 {
		return fmt.Errorf("invalid CV V2 receiver registry generation parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return err
	}
	if err := cvValidateDistinctReceiverIDs(receiverIDs, false); err != nil {
		return err
	}
	ordered := sortedCopy(receiverIDs)
	if !equalInts(ordered, receiverIDs) {
		return fmt.Errorf("CV V2 receiver registry requires canonical receiver order")
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
	paths := []string{filepath.Join(publicDir, cvReceiverRegistryScalarFilename)}
	for _, id := range receiverIDs {
		paths = append(paths, cvReceiverScalarEncryptionSecretPath(secretDir, id), cvReceiverScalarIdentitySecretPath(secretDir, id))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CV V2 receiver key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	registry := cvReceiverRegistryScalar{Version: cvReceiverRegistryScalarVersion, SID: sid, Epoch: epoch,
		Receivers: make([]cvReceiverRegistryEntryScalar, len(receiverIDs))}
	encryptionSecrets := make([][]byte, len(receiverIDs))
	identitySecrets := make([][]byte, len(receiverIDs))
	seen := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, len(receiverIDs))
	for i, id := range receiverIDs {
		secret, err := cvRandomReceiverSecret()
		if err != nil {
			return err
		}
		publicKey, err := cvReceiverPublicKey(secret)
		if err != nil {
			return err
		}
		encodedPublic := publicKey.Bytes()
		if _, exists := seen[encodedPublic]; exists {
			return fmt.Errorf("duplicate generated CV V2 receiver encryption key")
		}
		seen[encodedPublic] = struct{}{}
		proof, err := cvProveReceiverEncryptionKeyScalar(sid, epoch, id, i+1, secret, &publicKey)
		if err != nil {
			return err
		}
		identityPublic, identitySecret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate CV V2 receiver identity key: %w", err)
		}
		encodedSecret := secret.Bytes()
		encryptionSecrets[i] = append([]byte(nil), encodedSecret[:]...)
		identitySecrets[i] = append([]byte(nil), identitySecret...)
		registry.Receivers[i] = cvReceiverRegistryEntryScalar{
			ReceiverID: id, ReceiverIndex: i + 1,
			EncryptionPublic:   hex.EncodeToString(encodedPublic[:]),
			EncryptionKeyProof: hex.EncodeToString(proof),
			IdentityPublic:     hex.EncodeToString(identityPublic),
		}
	}
	if _, err := cvReceiverRegistryScalarDigest(&registry); err != nil {
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
	for i, id := range receiverIDs {
		path := cvReceiverScalarEncryptionSecretPath(secretDir, id)
		if err := cvWriteExclusiveKeyFile(path, encryptionSecrets[i], 0o600); err != nil {
			cleanup()
			return err
		}
		created = append(created, path)
		path = cvReceiverScalarIdentitySecretPath(secretDir, id)
		if err := cvWriteExclusiveKeyFile(path, identitySecrets[i], 0o600); err != nil {
			cleanup()
			return err
		}
		created = append(created, path)
	}
	if err := cvWriteExclusiveKeyFile(filepath.Join(publicDir, cvReceiverRegistryScalarFilename), raw, 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func cvReceiverRegistryScalarDigest(registry *cvReceiverRegistryScalar) ([]byte, error) {
	if registry == nil || registry.Version != cvReceiverRegistryScalarVersion || registry.SID == "" || registry.Epoch == 0 || len(registry.Receivers) == 0 {
		return nil, fmt.Errorf("invalid CV V2 receiver registry")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(registry.SID))
	cvWriteUint64(&wire, registry.Epoch)
	_ = cvWriteUint32(&wire, len(registry.Receivers))
	for i, entry := range registry.Receivers {
		if entry.ReceiverID < 0 || entry.ReceiverIndex != i+1 {
			return nil, fmt.Errorf("invalid CV V2 receiver registry index")
		}
		publicKey, err := cvDecodeCanonicalG1(entry.EncryptionPublic)
		if err != nil {
			return nil, err
		}
		proof, err := hex.DecodeString(entry.EncryptionKeyProof)
		if err != nil || hex.EncodeToString(proof) != entry.EncryptionKeyProof {
			return nil, fmt.Errorf("invalid CV V2 receiver encryption PoK encoding")
		}
		identityPublic, err := hex.DecodeString(entry.IdentityPublic)
		if err != nil || len(identityPublic) != ed25519.PublicKeySize || hex.EncodeToString(identityPublic) != entry.IdentityPublic {
			return nil, fmt.Errorf("invalid CV V2 receiver identity public key")
		}
		cvWriteUint64(&wire, uint64(entry.ReceiverID))
		cvWriteUint64(&wire, uint64(entry.ReceiverIndex))
		cvWritePoint(&wire, &publicKey)
		_ = cvWriteBytes(&wire, proof)
		_ = cvWriteBytes(&wire, identityPublic)
	}
	return hashBytes([]byte(cvReceiverRegistryScalarDomain), wire.Bytes()), nil
}

func cvLoadReceiverRegistryScalar(
	publicDir, secretDir, sid string, epoch uint64, expectedReceiverIDs, localReceiverIDs []int,
) (*cvReceiverKeyMaterialScalar, error) {
	if publicDir == "" || secretDir == "" || sid == "" || epoch == 0 || len(expectedReceiverIDs) == 0 {
		return nil, fmt.Errorf("invalid CV V2 receiver registry loading parameters")
	}
	if err := cvRequireSeparateKeyDirs(publicDir, secretDir); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(expectedReceiverIDs, false); err != nil {
		return nil, err
	}
	if err := cvValidateDistinctReceiverIDs(localReceiverIDs, true); err != nil {
		return nil, err
	}
	ordered := sortedCopy(expectedReceiverIDs)
	if !equalInts(ordered, expectedReceiverIDs) {
		return nil, fmt.Errorf("CV V2 receiver registry requires canonical receiver order")
	}
	raw, err := cvReadBoundedRegularFile(filepath.Join(publicDir, cvReceiverRegistryScalarFilename), cvMaxReceiverRegistryScalarBytes)
	if err != nil {
		return nil, err
	}
	var registry cvReceiverRegistryScalar
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid CV V2 receiver registry suffix")
	}
	canonical, err := json.MarshalIndent(registry, "", "  ")
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return nil, fmt.Errorf("non-canonical CV V2 receiver registry")
	}
	if registry.Version != cvReceiverRegistryScalarVersion || registry.SID != sid || registry.Epoch != epoch || len(registry.Receivers) != len(expectedReceiverIDs) {
		return nil, fmt.Errorf("CV V2 receiver registry context mismatch")
	}
	material := &cvReceiverKeyMaterialScalar{
		receiverOrder: append([]int(nil), expectedReceiverIDs...), receiverIndex: make(map[int]int, len(expectedReceiverIDs)),
		encryptionPublicKeys: make([]bls12381.G1Affine, len(expectedReceiverIDs)), identityPublicKeys: make([]ed25519.PublicKey, len(expectedReceiverIDs)),
		localEncryptionSecrets: make(map[int]fr.Element, len(localReceiverIDs)), localIdentitySecrets: make(map[int]ed25519.PrivateKey, len(localReceiverIDs)),
		sid: sid, epoch: epoch,
	}
	seenEncryption := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, len(expectedReceiverIDs))
	seenIdentity := make(map[string]struct{}, len(expectedReceiverIDs))
	for i, entry := range registry.Receivers {
		if entry.ReceiverID != expectedReceiverIDs[i] || entry.ReceiverIndex != i+1 {
			return nil, fmt.Errorf("CV V2 receiver registry order/index mismatch")
		}
		publicKey, err := cvDecodeCanonicalG1(entry.EncryptionPublic)
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 receiver encryption public key: %w", err)
		}
		proof, err := hex.DecodeString(entry.EncryptionKeyProof)
		if err != nil || hex.EncodeToString(proof) != entry.EncryptionKeyProof {
			return nil, fmt.Errorf("invalid CV V2 receiver encryption PoK encoding")
		}
		if err := cvVerifyReceiverEncryptionKeyScalar(sid, epoch, entry.ReceiverID, entry.ReceiverIndex, &publicKey, proof); err != nil {
			return nil, err
		}
		encoded := publicKey.Bytes()
		if _, duplicate := seenEncryption[encoded]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 receiver encryption public key")
		}
		seenEncryption[encoded] = struct{}{}
		identityPublic, err := hex.DecodeString(entry.IdentityPublic)
		if err != nil || len(identityPublic) != ed25519.PublicKeySize || hex.EncodeToString(identityPublic) != entry.IdentityPublic {
			return nil, fmt.Errorf("invalid CV V2 receiver identity public key")
		}
		identity := ed25519.PublicKey(append([]byte(nil), identityPublic...))
		if _, duplicate := seenIdentity[string(identity)]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 receiver identity public key")
		}
		seenIdentity[string(identity)] = struct{}{}
		material.receiverIndex[entry.ReceiverID] = entry.ReceiverIndex
		material.encryptionPublicKeys[i] = publicKey
		material.identityPublicKeys[i] = identity
	}
	material.registryDigest, err = cvReceiverRegistryScalarDigest(&registry)
	if err != nil {
		return nil, err
	}
	for _, id := range localReceiverIDs {
		index, ok := material.receiverIndex[id]
		if !ok {
			return nil, fmt.Errorf("local CV V2 receiver %d is outside registry", id)
		}
		encryptionRaw, err := cvReadReceiverSecret(cvReceiverScalarEncryptionSecretPath(secretDir, id))
		if err != nil {
			return nil, err
		}
		var secret fr.Element
		if err := secret.SetBytesCanonical(encryptionRaw); err != nil || secret.IsZero() {
			return nil, fmt.Errorf("invalid CV V2 receiver encryption secret")
		}
		publicKey, _ := cvReceiverPublicKey(secret)
		if !publicKey.Equal(&material.encryptionPublicKeys[index-1]) {
			return nil, fmt.Errorf("CV V2 receiver encryption secret/public mismatch")
		}
		material.localEncryptionSecrets[id] = secret
		identityRaw, err := cvReadReceiverScalarIdentitySecret(cvReceiverScalarIdentitySecretPath(secretDir, id))
		if err != nil || len(identityRaw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid CV V2 receiver identity secret")
		}
		identitySecret := ed25519.PrivateKey(append([]byte(nil), identityRaw...))
		if !bytes.Equal(identitySecret.Public().(ed25519.PublicKey), material.identityPublicKeys[index-1]) {
			return nil, fmt.Errorf("CV V2 receiver identity secret/public mismatch")
		}
		material.localIdentitySecrets[id] = identitySecret
	}
	return material, nil
}

func cvReadReceiverScalarIdentitySecret(path string) ([]byte, error) {
	file, info, err := cvOpenRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid CV V2 receiver identity secret file")
	}
	secret := make([]byte, ed25519.PrivateKeySize)
	if _, err := io.ReadFull(file, secret); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("CV V2 receiver identity secret changed size while reading")
	}
	return secret, nil
}

// equalInts is kept local to this scalar protocol key/registry implementation so a caller
// cannot accidentally treat a sorted registry as an unordered set.
func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
