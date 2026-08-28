package core

import (
	"bytes"
	"context"
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
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const thresholdCoinSetupVersion = 2

type thresholdCoinKeySet struct {
	threshold       int
	nodeIDs         []int
	nodeIndex       map[int]int
	groupPublic     bls12381.G2Affine
	sharePublic     []bls12381.G2Affine
	privateShare    map[int]fr.Element
	lowThreshold    int
	lowGroupPublic  bls12381.G2Affine
	lowSharePublic  []bls12381.G2Affine
	lowPrivateShare map[int]fr.Element
}

type thresholdCoinPublicArtifact struct {
	Version         int      `json:"version"`
	Threshold       int      `json:"threshold"`
	NodeIDs         []int    `json:"node_ids"`
	GroupPublic     []byte   `json:"group_public"`
	SharePublics    [][]byte `json:"share_publics"`
	LowThreshold    int      `json:"low_threshold"`
	LowGroupPublic  []byte   `json:"low_group_public"`
	LowSharePublics [][]byte `json:"low_share_publics"`
}

type thresholdCoinPrivateArtifact struct {
	Version      int    `json:"version"`
	NodeID       int    `json:"node_id"`
	Index        int    `json:"index"`
	PublicDigest []byte `json:"public_digest"`
	Share        []byte `json:"share"`
	LowShare     []byte `json:"low_share"`
}

var thresholdCoinKeyCache sync.Map

func PrewarmPracticalThresholdCoin(cfg Config) error {
	old := append([]int(nil), cfg.OldCommittee...)
	sort.Ints(old)
	_, err := loadOrCreateThresholdCoinKeys(cfg, old)
	return err
}

func loadOrCreateThresholdCoinKeys(cfg Config, old []int) (*thresholdCoinKeySet, error) {
	if len(old) == 0 || cfg.F < 0 || len(old) < 3*cfg.F+1 {
		return nil, fmt.Errorf("invalid threshold coin committee")
	}
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	localIDs := thresholdCoinLocalOldIDs(cfg, old)
	if cfg.StrictNetwork && len(localIDs) == 0 {
		return nil, fmt.Errorf("strict threshold coin setup has no local old-committee identity")
	}
	cacheKey := thresholdCoinMemoryCacheKey(cacheDir, old, cfg.F, cfg.StrictNetwork, localIDs)
	if cached, ok := thresholdCoinKeyCache.Load(cacheKey); ok {
		return cached.(*thresholdCoinKeySet), nil
	}

	if cacheDir == "" {
		if cfg.StrictNetwork {
			return nil, fmt.Errorf("strict threshold coin setup requires PRACTICAL_ARTIFACT_CACHE_DIR")
		}
		keys, err := generateThresholdCoinKeys(old, cfg.F)
		if err != nil {
			return nil, err
		}
		thresholdCoinKeyCache.Store(cacheKey, keys)
		return keys, nil
	}

	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create threshold coin setup directory: %w", err)
	}
	publicPath := thresholdCoinPublicPath(cacheDir, old, cfg.F)
	lockPath := publicPath + ".lock"
	if _, _, err := readThresholdCoinPublicArtifact(publicPath); err != nil {
		if practicalSetupReadOnly() {
			return nil, fmt.Errorf("read-only Practical setup is missing threshold coin public artifact: %w", err)
		}
		lock, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if lockErr == nil {
			_, _ = lock.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
			_ = lock.Close()
			generated, genErr := generateThresholdCoinKeys(old, cfg.F)
			if genErr == nil {
				genErr = writeThresholdCoinArtifacts(publicPath, generated)
			}
			_ = os.Remove(lockPath)
			if genErr != nil {
				return nil, genErr
			}
		} else if !errors.Is(lockErr, os.ErrExist) {
			return nil, fmt.Errorf("create threshold coin setup lock: %w", lockErr)
		}
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		public, raw, err := readThresholdCoinPublicArtifact(publicPath)
		if err == nil {
			loadIDs := old
			if cfg.StrictNetwork {
				loadIDs = localIDs
			}
			keys, keyErr := thresholdCoinKeysFromArtifacts(publicPath, public, raw, loadIDs)
			if keyErr == nil {
				thresholdCoinKeyCache.Store(cacheKey, keys)
				return keys, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("waiting for threshold coin setup: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func thresholdCoinLocalOldIDs(cfg Config, old []int) []int {
	localSet := parseNodeIDSet(cfg.MVBALocalNodeIDs)
	if len(localSet) == 0 {
		localSet = parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	}
	out := make([]int, 0, len(localSet))
	for _, id := range old {
		if _, ok := localSet[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func generateThresholdCoinKeys(old []int, f int) (*thresholdCoinKeySet, error) {
	high, err := generateThresholdCoinMaterial(old, len(old)-f)
	if err != nil {
		return nil, err
	}
	low, err := generateThresholdCoinMaterial(old, f+1)
	if err != nil {
		return nil, err
	}
	return &thresholdCoinKeySet{
		threshold: high.threshold, nodeIDs: append([]int(nil), old...), nodeIndex: high.nodeIndex,
		groupPublic: high.groupPublic, sharePublic: high.sharePublic, privateShare: high.privateShare,
		lowThreshold: low.threshold, lowGroupPublic: low.groupPublic, lowSharePublic: low.sharePublic,
		lowPrivateShare: low.privateShare,
	}, nil
}

type thresholdCoinMaterial struct {
	threshold    int
	nodeIndex    map[int]int
	groupPublic  bls12381.G2Affine
	sharePublic  []bls12381.G2Affine
	privateShare map[int]fr.Element
}

func generateThresholdCoinMaterial(old []int, threshold int) (*thresholdCoinMaterial, error) {
	if threshold <= 0 || threshold > len(old) {
		return nil, fmt.Errorf("invalid threshold coin threshold=%d", threshold)
	}
	var coefficients []fr.Element
	for {
		coefficients = make([]fr.Element, threshold)
		for i := range coefficients {
			if _, err := coefficients[i].SetRandom(); err != nil {
				return nil, fmt.Errorf("sample threshold coin coefficient: %w", err)
			}
		}
		if coefficients[0].IsZero() || (threshold > 1 && coefficients[threshold-1].IsZero()) {
			continue
		}
		break
	}
	shares := make([]fr.Element, len(old))
	for i := range old {
		var x fr.Element
		x.SetInt64(int64(i + 1))
		var xPower fr.Element
		xPower.SetOne()
		for j := range coefficients {
			var term fr.Element
			term.Mul(&coefficients[j], &xPower)
			shares[i].Add(&shares[i], &term)
			xPower.Mul(&xPower, &x)
		}
	}
	_, _, _, g2 := bls12381.Generators()
	sharePublic := make([]bls12381.G2Affine, len(old))
	private := make(map[int]fr.Element, len(old))
	index := make(map[int]int, len(old))
	for i, id := range old {
		sharePublic[i].ScalarMultiplication(&g2, shares[i].BigInt(new(big.Int)))
		private[id] = shares[i]
		index[id] = i
	}
	var groupPublic bls12381.G2Affine
	groupPublic.ScalarMultiplication(&g2, coefficients[0].BigInt(new(big.Int)))
	return &thresholdCoinMaterial{threshold: threshold, nodeIndex: index, groupPublic: groupPublic, sharePublic: sharePublic, privateShare: private}, nil
}

func thresholdCoinPublicPath(cacheDir string, old []int, f int) string {
	key := struct {
		Version int   `json:"version"`
		Old     []int `json:"old"`
		F       int   `json:"f"`
	}{thresholdCoinSetupVersion, append([]int(nil), old...), f}
	raw, _ := json.Marshal(&key)
	digest := sha256.Sum256(raw)
	return filepath.Join(cacheDir, "threshold-coin-"+hex.EncodeToString(digest[:12])+".public.json")
}

func thresholdCoinPrivatePath(publicPath string, nodeID int) string {
	return fmt.Sprintf("%s.node-%06d.private.json", strings.TrimSuffix(publicPath, ".public.json"), nodeID)
}

func writeThresholdCoinArtifacts(publicPath string, keys *thresholdCoinKeySet) error {
	public := thresholdCoinPublicArtifact{
		Version:         thresholdCoinSetupVersion,
		Threshold:       keys.threshold,
		NodeIDs:         append([]int(nil), keys.nodeIDs...),
		GroupPublic:     keys.groupPublic.Marshal(),
		SharePublics:    make([][]byte, len(keys.sharePublic)),
		LowThreshold:    keys.lowThreshold,
		LowGroupPublic:  keys.lowGroupPublic.Marshal(),
		LowSharePublics: make([][]byte, len(keys.lowSharePublic)),
	}
	for i := range keys.sharePublic {
		public.SharePublics[i] = keys.sharePublic[i].Marshal()
	}
	for i := range keys.lowSharePublic {
		public.LowSharePublics[i] = keys.lowSharePublic[i].Marshal()
	}
	publicRaw, err := json.Marshal(&public)
	if err != nil {
		return err
	}
	publicDigest := sha256.Sum256(publicRaw)
	for i, id := range keys.nodeIDs {
		share := keys.privateShare[id]
		lowShare := keys.lowPrivateShare[id]
		private := thresholdCoinPrivateArtifact{
			Version:      thresholdCoinSetupVersion,
			NodeID:       id,
			Index:        i,
			PublicDigest: append([]byte(nil), publicDigest[:]...),
			Share:        share.Marshal(),
			LowShare:     lowShare.Marshal(),
		}
		raw, marshalErr := json.Marshal(&private)
		if marshalErr != nil {
			return marshalErr
		}
		if err := writeThresholdCoinArtifact(thresholdCoinPrivatePath(publicPath, id), raw, 0o600); err != nil {
			return err
		}
	}
	return writeThresholdCoinArtifact(publicPath, publicRaw, 0o644)
}

func writeThresholdCoinArtifact(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".threshold-coin-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func readThresholdCoinPublicArtifact(path string) (*thresholdCoinPublicArtifact, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var artifact thresholdCoinPublicArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, nil, err
	}
	if artifact.Version != thresholdCoinSetupVersion || artifact.Threshold <= 0 ||
		artifact.LowThreshold <= 0 || len(artifact.NodeIDs) == 0 ||
		len(artifact.SharePublics) != len(artifact.NodeIDs) ||
		len(artifact.LowSharePublics) != len(artifact.NodeIDs) {
		return nil, nil, fmt.Errorf("invalid threshold coin public artifact")
	}
	return &artifact, raw, nil
}

func thresholdCoinKeysFromArtifacts(
	publicPath string,
	artifact *thresholdCoinPublicArtifact,
	publicRaw []byte,
	loadIDs []int,
) (*thresholdCoinKeySet, error) {
	var groupPublic bls12381.G2Affine
	if err := groupPublic.Unmarshal(artifact.GroupPublic); err != nil {
		return nil, fmt.Errorf("decode threshold coin group public key: %w", err)
	}
	sharePublic := make([]bls12381.G2Affine, len(artifact.SharePublics))
	lowSharePublic := make([]bls12381.G2Affine, len(artifact.LowSharePublics))
	nodeIndex := make(map[int]int, len(artifact.NodeIDs))
	for i, raw := range artifact.SharePublics {
		if i > 0 && artifact.NodeIDs[i-1] >= artifact.NodeIDs[i] {
			return nil, fmt.Errorf("threshold coin node IDs are not canonical")
		}
		if err := sharePublic[i].Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("decode threshold coin share public key: %w", err)
		}
		nodeIndex[artifact.NodeIDs[i]] = i
	}
	var lowGroupPublic bls12381.G2Affine
	if err := lowGroupPublic.Unmarshal(artifact.LowGroupPublic); err != nil {
		return nil, fmt.Errorf("decode low threshold coin group public key: %w", err)
	}
	for i, raw := range artifact.LowSharePublics {
		if err := lowSharePublic[i].Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("decode low threshold coin share public key: %w", err)
		}
	}
	publicDigest := sha256.Sum256(publicRaw)
	privateShares := make(map[int]fr.Element, len(loadIDs))
	lowPrivateShares := make(map[int]fr.Element, len(loadIDs))
	_, _, _, g2 := bls12381.Generators()
	for _, id := range loadIDs {
		index, ok := nodeIndex[id]
		if !ok {
			return nil, fmt.Errorf("threshold coin private identity %d is not in committee", id)
		}
		raw, err := os.ReadFile(thresholdCoinPrivatePath(publicPath, id))
		if err != nil {
			return nil, err
		}
		var private thresholdCoinPrivateArtifact
		if err := json.Unmarshal(raw, &private); err != nil {
			return nil, err
		}
		if private.Version != thresholdCoinSetupVersion || private.NodeID != id || private.Index != index ||
			!bytes.Equal(private.PublicDigest, publicDigest[:]) {
			return nil, fmt.Errorf("threshold coin private artifact binding mismatch for node %d", id)
		}
		var share fr.Element
		if err := share.SetBytesCanonical(private.Share); err != nil {
			return nil, fmt.Errorf("decode threshold coin private share for node %d: %w", id, err)
		}
		var expected bls12381.G2Affine
		expected.ScalarMultiplication(&g2, share.BigInt(new(big.Int)))
		if !bytes.Equal(expected.Marshal(), sharePublic[index].Marshal()) {
			return nil, fmt.Errorf("threshold coin private/public share mismatch for node %d", id)
		}
		privateShares[id] = share
		var lowShare fr.Element
		if err := lowShare.SetBytesCanonical(private.LowShare); err != nil {
			return nil, fmt.Errorf("decode low threshold coin private share for node %d: %w", id, err)
		}
		var expectedLow bls12381.G2Affine
		expectedLow.ScalarMultiplication(&g2, lowShare.BigInt(new(big.Int)))
		if !bytes.Equal(expectedLow.Marshal(), lowSharePublic[index].Marshal()) {
			return nil, fmt.Errorf("low threshold coin private/public share mismatch for node %d", id)
		}
		lowPrivateShares[id] = lowShare
	}
	return &thresholdCoinKeySet{
		threshold:       artifact.Threshold,
		nodeIDs:         append([]int(nil), artifact.NodeIDs...),
		nodeIndex:       nodeIndex,
		groupPublic:     groupPublic,
		sharePublic:     sharePublic,
		privateShare:    privateShares,
		lowThreshold:    artifact.LowThreshold,
		lowGroupPublic:  lowGroupPublic,
		lowSharePublic:  lowSharePublic,
		lowPrivateShare: lowPrivateShares,
	}, nil
}

func thresholdCoinMemoryCacheKey(cacheDir string, old []int, f int, strict bool, localIDs []int) string {
	key := struct {
		CacheDir string `json:"cache_dir"`
		Old      []int  `json:"old"`
		F        int    `json:"f"`
		Strict   bool   `json:"strict"`
		Local    []int  `json:"local"`
	}{cacheDir, append([]int(nil), old...), f, strict, append([]int(nil), localIDs...)}
	raw, _ := json.Marshal(&key)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
