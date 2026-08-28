package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

const practicalCompKeyVersion = 1

type practicalCompKeySet struct {
	nodeIDs []int
	public  map[int][]byte
	private map[int]*big.Int
}

type practicalCompPublicArtifact struct {
	Version int            `json:"version"`
	NodeIDs []int          `json:"node_ids"`
	Public  map[int][]byte `json:"public"`
}

type practicalCompPrivateArtifact struct {
	Version      int    `json:"version"`
	NodeID       int    `json:"node_id"`
	PublicDigest []byte `json:"public_digest"`
	Scalar       []byte `json:"scalar"`
}

func loadOrCreatePracticalCompKeys(cfg Config, newCommittee []int) (*practicalCompKeySet, error) {
	nodes := append([]int(nil), newCommittee...)
	sort.Ints(nodes)
	if len(nodes) == 0 {
		return nil, errors.New("empty CompProve committee")
	}
	localIDs := practicalCompLocalIDs(cfg, nodes)
	if cfg.StrictNetwork && len(localIDs) == 0 {
		return nil, errors.New("strict CompProve setup has no local new-committee identity")
	}
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		if cfg.StrictNetwork {
			return nil, errors.New("strict CompProve setup requires PRACTICAL_ARTIFACT_CACHE_DIR")
		}
		return generatePracticalCompKeys(nodes)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create CompProve setup directory: %w", err)
	}
	publicPath := practicalCompPublicPath(cacheDir, nodes)
	lockPath := publicPath + ".lock"
	if _, _, err := readPracticalCompPublic(publicPath); err != nil {
		if practicalSetupReadOnly() {
			return nil, fmt.Errorf("read-only Practical setup is missing CompProve public artifact: %w", err)
		}
		lock, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if lockErr == nil {
			_, _ = lock.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
			_ = lock.Close()
			keys, genErr := generatePracticalCompKeys(nodes)
			if genErr == nil {
				genErr = writePracticalCompArtifacts(publicPath, keys)
			}
			_ = os.Remove(lockPath)
			if genErr != nil {
				return nil, genErr
			}
		} else if !errors.Is(lockErr, os.ErrExist) {
			return nil, fmt.Errorf("create CompProve setup lock: %w", lockErr)
		}
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		public, raw, err := readPracticalCompPublic(publicPath)
		if err == nil {
			loadIDs := nodes
			if cfg.StrictNetwork {
				loadIDs = localIDs
			}
			keys, loadErr := practicalCompKeysFromArtifacts(publicPath, public, raw, loadIDs)
			if loadErr == nil {
				return keys, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("waiting for CompProve setup: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func practicalCompLocalIDs(cfg Config, committee []int) []int {
	configured := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	out := make([]int, 0, len(configured))
	for _, id := range committee {
		if _, ok := configured[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func generatePracticalCompKeys(nodes []int) (*practicalCompKeySet, error) {
	curve := elliptic.P256()
	public := make(map[int][]byte, len(nodes))
	private := make(map[int]*big.Int, len(nodes))
	for _, id := range nodes {
		sk, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate CompProve key for node %d: %w", id, err)
		}
		public[id] = elliptic.MarshalCompressed(curve, sk.X, sk.Y)
		private[id] = new(big.Int).Set(sk.D)
	}
	return &practicalCompKeySet{nodeIDs: append([]int(nil), nodes...), public: public, private: private}, nil
}

func practicalCompPublicPath(cacheDir string, nodes []int) string {
	key := struct {
		Version int   `json:"version"`
		Nodes   []int `json:"nodes"`
	}{practicalCompKeyVersion, append([]int(nil), nodes...)}
	raw, _ := json.Marshal(&key)
	digest := sha256.Sum256(raw)
	return filepath.Join(cacheDir, "comp-elgamal-"+hex.EncodeToString(digest[:12])+".public.json")
}

func practicalCompPrivatePath(publicPath string, nodeID int) string {
	return fmt.Sprintf("%s.node-%06d.private.json", strings.TrimSuffix(publicPath, ".public.json"), nodeID)
}

func writePracticalCompArtifacts(publicPath string, keys *practicalCompKeySet) error {
	artifact := practicalCompPublicArtifact{
		Version: practicalCompKeyVersion,
		NodeIDs: append([]int(nil), keys.nodeIDs...),
		Public:  make(map[int][]byte, len(keys.public)),
	}
	for id, public := range keys.public {
		artifact.Public[id] = append([]byte(nil), public...)
	}
	publicRaw, err := json.Marshal(&artifact)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(publicRaw)
	for _, id := range keys.nodeIDs {
		private := practicalCompPrivateArtifact{
			Version:      practicalCompKeyVersion,
			NodeID:       id,
			PublicDigest: append([]byte(nil), digest[:]...),
			Scalar:       keys.private[id].Bytes(),
		}
		raw, marshalErr := json.Marshal(&private)
		if marshalErr != nil {
			return marshalErr
		}
		if err := writeThresholdCoinArtifact(practicalCompPrivatePath(publicPath, id), raw, 0o600); err != nil {
			return err
		}
	}
	return writeThresholdCoinArtifact(publicPath, publicRaw, 0o644)
}

func readPracticalCompPublic(path string) (*practicalCompPublicArtifact, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var artifact practicalCompPublicArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, nil, err
	}
	if artifact.Version != practicalCompKeyVersion || len(artifact.NodeIDs) == 0 || len(artifact.Public) != len(artifact.NodeIDs) {
		return nil, nil, errors.New("invalid CompProve public artifact")
	}
	curve := elliptic.P256()
	for i, id := range artifact.NodeIDs {
		if i > 0 && artifact.NodeIDs[i-1] >= id {
			return nil, nil, errors.New("non-canonical CompProve committee")
		}
		x, _ := elliptic.UnmarshalCompressed(curve, artifact.Public[id])
		if x == nil {
			return nil, nil, fmt.Errorf("invalid CompProve public key for node %d", id)
		}
	}
	return &artifact, raw, nil
}

func practicalCompKeysFromArtifacts(
	publicPath string,
	artifact *practicalCompPublicArtifact,
	publicRaw []byte,
	loadIDs []int,
) (*practicalCompKeySet, error) {
	keys := &practicalCompKeySet{
		nodeIDs: append([]int(nil), artifact.NodeIDs...),
		public:  make(map[int][]byte, len(artifact.Public)),
		private: make(map[int]*big.Int, len(loadIDs)),
	}
	for id, public := range artifact.Public {
		keys.public[id] = append([]byte(nil), public...)
	}
	digest := sha256.Sum256(publicRaw)
	curve := elliptic.P256()
	for _, id := range loadIDs {
		raw, err := os.ReadFile(practicalCompPrivatePath(publicPath, id))
		if err != nil {
			return nil, err
		}
		var private practicalCompPrivateArtifact
		if err := json.Unmarshal(raw, &private); err != nil {
			return nil, err
		}
		if private.Version != practicalCompKeyVersion || private.NodeID != id || !bytes.Equal(private.PublicDigest, digest[:]) {
			return nil, fmt.Errorf("CompProve private artifact mismatch for node %d", id)
		}
		scalar := new(big.Int).SetBytes(private.Scalar)
		if scalar.Sign() <= 0 || scalar.Cmp(curve.Params().N) >= 0 {
			return nil, fmt.Errorf("invalid CompProve private scalar for node %d", id)
		}
		x, y := curve.ScalarBaseMult(scalar.Bytes())
		if !bytes.Equal(elliptic.MarshalCompressed(curve, x, y), keys.public[id]) {
			return nil, fmt.Errorf("CompProve private/public mismatch for node %d", id)
		}
		keys.private[id] = scalar
	}
	return keys, nil
}
