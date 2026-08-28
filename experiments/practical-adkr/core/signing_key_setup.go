package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const practicalSigningKeyVersion = 1

const (
	dealerECDSARole    = "dealer-ecdsa"
	oldEd25519Role     = "old-ed25519"
	recipientECDSARole = "recipient-ecdsa"
)

// practicalSigningKeySet separates committee-wide verification material from
// process-local signing/decryption material. The deterministic key generator
// is benchmark setup only; production deployments must import an equivalent
// public bundle and provision each private key directly to its owner.
type practicalSigningKeySet struct {
	dealerECDSAPublic  map[int]*ecdsa.PublicKey
	dealerECDSAPrivate map[int]*ecdsa.PrivateKey
	oldEdPublic        map[int]ed25519.PublicKey
	oldEdPrivate       map[int]ed25519.PrivateKey
	recipientPublic    map[int]*ecdsa.PublicKey
	recipientPrivate   map[int]*ecdsa.PrivateKey
}

func loadPracticalSigningKeys(cfg Config, oldCommittee, newCommittee []int) (*practicalSigningKeySet, error) {
	if len(oldCommittee) == 0 || len(newCommittee) == 0 {
		return nil, errors.New("signing key setup requires non-empty committees")
	}
	if cfg.StrictNetwork {
		return loadOrCreateStrictPracticalSigningKeys(cfg, oldCommittee, newCommittee)
	}
	local := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	retainPrivate := func(id int) bool {
		return true
	}
	_ = local

	seed := benchmarkSeed()
	keys := &practicalSigningKeySet{
		dealerECDSAPublic:  make(map[int]*ecdsa.PublicKey, len(oldCommittee)),
		dealerECDSAPrivate: make(map[int]*ecdsa.PrivateKey),
		oldEdPublic:        make(map[int]ed25519.PublicKey, len(oldCommittee)),
		oldEdPrivate:       make(map[int]ed25519.PrivateKey),
		recipientPublic:    make(map[int]*ecdsa.PublicKey, len(newCommittee)),
		recipientPrivate:   make(map[int]*ecdsa.PrivateKey),
	}
	for _, id := range oldCommittee {
		ecdsaKey, err := setupECDSAKey(seed, "practical-adkr:dealer-ecdsa", id)
		if err != nil {
			return nil, fmt.Errorf("setup dealer ECDSA key %d: %w", id, err)
		}
		keys.dealerECDSAPublic[id] = &ecdsaKey.PublicKey
		if retainPrivate(id) {
			keys.dealerECDSAPrivate[id] = ecdsaKey
		}

		edPublic, edPrivate, err := setupEd25519Key(seed, "practical-adkr:dealer-ed25519", id)
		if err != nil {
			return nil, fmt.Errorf("setup old-node Ed25519 key %d: %w", id, err)
		}
		keys.oldEdPublic[id] = edPublic
		if retainPrivate(id) {
			keys.oldEdPrivate[id] = edPrivate
		}
	}
	for _, id := range newCommittee {
		key, err := setupECDSAKey(seed, "practical-adkr:recipient-ecdsa", id)
		if err != nil {
			return nil, fmt.Errorf("setup recipient ECDSA key %d: %w", id, err)
		}
		keys.recipientPublic[id] = &key.PublicKey
		if retainPrivate(id) {
			keys.recipientPrivate[id] = key
		}
	}
	return keys, nil
}

type practicalSigningPublicArtifact struct {
	Version        int            `json:"version"`
	OldCommittee   []int          `json:"old_committee"`
	NewCommittee   []int          `json:"new_committee"`
	DealerECDSA    map[int][]byte `json:"dealer_ecdsa"`
	OldEd25519     map[int][]byte `json:"old_ed25519"`
	RecipientECDSA map[int][]byte `json:"recipient_ecdsa"`
}

type practicalSigningPrivateArtifact struct {
	Version      int    `json:"version"`
	Role         string `json:"role"`
	NodeID       int    `json:"node_id"`
	PublicDigest []byte `json:"public_digest"`
	Private      []byte `json:"private"`
}

func loadOrCreateStrictPracticalSigningKeys(cfg Config, oldCommittee, newCommittee []int) (*practicalSigningKeySet, error) {
	local := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(local) == 0 {
		return nil, errors.New("strict signing key setup requires local protocol identities")
	}
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		return nil, errors.New("strict signing key setup requires PRACTICAL_ARTIFACT_CACHE_DIR")
	}
	old := append([]int(nil), oldCommittee...)
	newC := append([]int(nil), newCommittee...)
	sort.Ints(old)
	sort.Ints(newC)
	publicPath := practicalSigningPublicPath(cacheDir, old, newC)
	lockPath := publicPath + ".lock"
	if _, _, err := readPracticalSigningPublic(publicPath, old, newC); err != nil {
		if practicalSetupReadOnly() {
			return nil, fmt.Errorf("read-only Practical setup is missing signing public artifact: %w", err)
		}
		lock, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if lockErr == nil {
			_, _ = lock.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
			_ = lock.Close()
			genErr := generatePracticalSigningArtifacts(publicPath, old, newC)
			_ = os.Remove(lockPath)
			if genErr != nil {
				return nil, genErr
			}
		} else if !errors.Is(lockErr, os.ErrExist) {
			return nil, fmt.Errorf("create signing setup lock: %w", lockErr)
		}
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		artifact, raw, err := readPracticalSigningPublic(publicPath, old, newC)
		if err == nil {
			keys, loadErr := practicalSigningKeysFromArtifacts(publicPath, artifact, raw, local)
			if loadErr == nil {
				return keys, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("waiting for signing setup: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func practicalSigningPublicPath(cacheDir string, oldCommittee, newCommittee []int) string {
	key := struct {
		Version int   `json:"version"`
		Old     []int `json:"old"`
		New     []int `json:"new"`
	}{practicalSigningKeyVersion, oldCommittee, newCommittee}
	raw, _ := json.Marshal(&key)
	digest := sha256.Sum256(raw)
	return filepath.Join(cacheDir, "signing-"+hex.EncodeToString(digest[:12])+".public.json")
}

func practicalSigningPrivatePath(publicPath, role string, nodeID int) string {
	return fmt.Sprintf("%s.%s-node-%06d.private.json", strings.TrimSuffix(publicPath, ".public.json"), role, nodeID)
}

func generatePracticalSigningArtifacts(publicPath string, oldCommittee, newCommittee []int) error {
	curve := elliptic.P256()
	artifact := practicalSigningPublicArtifact{
		Version: practicalSigningKeyVersion, OldCommittee: oldCommittee, NewCommittee: newCommittee,
		DealerECDSA:    make(map[int][]byte, len(oldCommittee)),
		OldEd25519:     make(map[int][]byte, len(oldCommittee)),
		RecipientECDSA: make(map[int][]byte, len(newCommittee)),
	}
	private := make(map[string]map[int][]byte, 3)
	private[dealerECDSARole] = make(map[int][]byte, len(oldCommittee))
	private[oldEd25519Role] = make(map[int][]byte, len(oldCommittee))
	private[recipientECDSARole] = make(map[int][]byte, len(newCommittee))
	for _, id := range oldCommittee {
		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		artifact.DealerECDSA[id] = elliptic.MarshalCompressed(curve, ecKey.X, ecKey.Y)
		private[dealerECDSARole][id] = ecKey.D.Bytes()
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		artifact.OldEd25519[id] = append([]byte(nil), edPub...)
		private[oldEd25519Role][id] = append([]byte(nil), edPriv...)
	}
	for _, id := range newCommittee {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		artifact.RecipientECDSA[id] = elliptic.MarshalCompressed(curve, key.X, key.Y)
		private[recipientECDSARole][id] = key.D.Bytes()
	}
	publicRaw, err := json.Marshal(&artifact)
	if err != nil {
		return err
	}
	publicDigest := sha256.Sum256(publicRaw)
	for role, byNode := range private {
		for id, material := range byNode {
			payload := practicalSigningPrivateArtifact{
				Version: practicalSigningKeyVersion, Role: role, NodeID: id,
				PublicDigest: append([]byte(nil), publicDigest[:]...), Private: material,
			}
			raw, marshalErr := json.Marshal(&payload)
			if marshalErr != nil {
				return marshalErr
			}
			if err := writeThresholdCoinArtifact(practicalSigningPrivatePath(publicPath, role, id), raw, 0o600); err != nil {
				return err
			}
		}
	}
	return writeThresholdCoinArtifact(publicPath, publicRaw, 0o644)
}

func readPracticalSigningPublic(path string, oldCommittee, newCommittee []int) (*practicalSigningPublicArtifact, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var artifact practicalSigningPublicArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, nil, err
	}
	if artifact.Version != practicalSigningKeyVersion || !equalIntSlices(artifact.OldCommittee, oldCommittee) || !equalIntSlices(artifact.NewCommittee, newCommittee) {
		return nil, nil, errors.New("signing public artifact committee mismatch")
	}
	if len(artifact.DealerECDSA) != len(oldCommittee) || len(artifact.OldEd25519) != len(oldCommittee) || len(artifact.RecipientECDSA) != len(newCommittee) {
		return nil, nil, errors.New("incomplete signing public artifact")
	}
	curve := elliptic.P256()
	for _, id := range oldCommittee {
		if x, _ := elliptic.UnmarshalCompressed(curve, artifact.DealerECDSA[id]); x == nil || len(artifact.OldEd25519[id]) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("invalid signing public key for old node %d", id)
		}
	}
	for _, id := range newCommittee {
		if x, _ := elliptic.UnmarshalCompressed(curve, artifact.RecipientECDSA[id]); x == nil {
			return nil, nil, fmt.Errorf("invalid recipient public key %d", id)
		}
	}
	return &artifact, raw, nil
}

func practicalSigningKeysFromArtifacts(publicPath string, artifact *practicalSigningPublicArtifact, publicRaw []byte, local map[int]struct{}) (*practicalSigningKeySet, error) {
	curve := elliptic.P256()
	keys := &practicalSigningKeySet{
		dealerECDSAPublic: make(map[int]*ecdsa.PublicKey, len(artifact.DealerECDSA)), dealerECDSAPrivate: make(map[int]*ecdsa.PrivateKey),
		oldEdPublic: make(map[int]ed25519.PublicKey, len(artifact.OldEd25519)), oldEdPrivate: make(map[int]ed25519.PrivateKey),
		recipientPublic: make(map[int]*ecdsa.PublicKey, len(artifact.RecipientECDSA)), recipientPrivate: make(map[int]*ecdsa.PrivateKey),
	}
	for id, encoded := range artifact.DealerECDSA {
		x, y := elliptic.UnmarshalCompressed(curve, encoded)
		keys.dealerECDSAPublic[id] = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}
	for id, encoded := range artifact.OldEd25519 {
		keys.oldEdPublic[id] = append(ed25519.PublicKey(nil), encoded...)
	}
	for id, encoded := range artifact.RecipientECDSA {
		x, y := elliptic.UnmarshalCompressed(curve, encoded)
		keys.recipientPublic[id] = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}
	digest := sha256.Sum256(publicRaw)
	for id := range local {
		if public := keys.dealerECDSAPublic[id]; public != nil {
			private, err := readPracticalECDSAPrivate(publicPath, dealerECDSARole, id, digest[:], public)
			if err != nil {
				return nil, err
			}
			keys.dealerECDSAPrivate[id] = private
		}
		if public := keys.oldEdPublic[id]; len(public) != 0 {
			private, err := readPracticalEd25519Private(publicPath, id, digest[:], public)
			if err != nil {
				return nil, err
			}
			keys.oldEdPrivate[id] = private
		}
		if public := keys.recipientPublic[id]; public != nil {
			private, err := readPracticalECDSAPrivate(publicPath, recipientECDSARole, id, digest[:], public)
			if err != nil {
				return nil, err
			}
			keys.recipientPrivate[id] = private
		}
	}
	return keys, nil
}

func readPracticalSigningPrivate(publicPath, role string, nodeID int, publicDigest []byte) ([]byte, error) {
	raw, err := os.ReadFile(practicalSigningPrivatePath(publicPath, role, nodeID))
	if err != nil {
		return nil, err
	}
	var artifact practicalSigningPrivateArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, err
	}
	if artifact.Version != practicalSigningKeyVersion || artifact.Role != role || artifact.NodeID != nodeID || !bytes.Equal(artifact.PublicDigest, publicDigest) {
		return nil, fmt.Errorf("signing private artifact mismatch role=%s node=%d", role, nodeID)
	}
	return artifact.Private, nil
}

func readPracticalECDSAPrivate(publicPath, role string, nodeID int, digest []byte, public *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	material, err := readPracticalSigningPrivate(publicPath, role, nodeID, digest)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(material)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid ECDSA private scalar role=%s node=%d", role, nodeID)
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	if x.Cmp(public.X) != 0 || y.Cmp(public.Y) != 0 {
		return nil, fmt.Errorf("ECDSA private/public mismatch role=%s node=%d", role, nodeID)
	}
	return &ecdsa.PrivateKey{PublicKey: *public, D: d}, nil
}

func readPracticalEd25519Private(publicPath string, nodeID int, digest []byte, public ed25519.PublicKey) (ed25519.PrivateKey, error) {
	material, err := readPracticalSigningPrivate(publicPath, oldEd25519Role, nodeID, digest)
	if err != nil {
		return nil, err
	}
	if len(material) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key node=%d", nodeID)
	}
	private := append(ed25519.PrivateKey(nil), material...)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return nil, fmt.Errorf("Ed25519 private/public mismatch node=%d", nodeID)
	}
	return private, nil
}

func equalIntSlices(left, right []int) bool {
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
