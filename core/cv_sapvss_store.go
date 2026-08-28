package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type cvComponentLeafStore struct {
	root string
}

type cvComponentShardStore struct {
	root string
}

type cvFreshShardStore struct {
	root string
}

func newCVComponentLeafStore(root string) (*cvComponentLeafStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV-sAPVSS component store root")
	}
	store := &cvComponentLeafStore{root: filepath.Join(root, "component-leaves")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func newCVComponentShardStore(root string) (*cvComponentShardStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV-sAPVSS component shard store root")
	}
	store := &cvComponentShardStore{root: filepath.Join(root, "component-shards")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func newCVFreshShardStore(root string) (*cvFreshShardStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV-sAPVSS fresh-shard store root")
	}
	store := &cvFreshShardStore{root: filepath.Join(root, "fresh-shards")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *cvComponentLeafStore) Put(
	sid string,
	epoch, dealer, holder int,
	leafDigest, leaf []byte,
) error {
	path, err := s.path(sid, epoch, dealer, holder, leafDigest)
	if err != nil {
		return err
	}
	return cvPutImmutableFile(path, leaf)
}

func (s *cvComponentLeafStore) Read(
	sid string,
	epoch, dealer, holder int,
	leafDigest []byte,
) ([]byte, error) {
	path, err := s.path(sid, epoch, dealer, holder, leafDigest)
	if err != nil {
		return nil, err
	}
	return cvReadImmutableFile(path)
}

func (s *cvComponentLeafStore) path(
	sid string,
	epoch, dealer, holder int,
	leafDigest []byte,
) (string, error) {
	if s == nil || dealer < 0 {
		return "", fmt.Errorf("invalid CV-sAPVSS component store key")
	}
	sidComponent, digest, err := cvStoreKeyParts(sid, epoch, holder, leafDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(
		s.root,
		sidComponent,
		fmt.Sprintf("epoch-%d", epoch),
		fmt.Sprintf("holder-%d", holder),
		fmt.Sprintf("dealer-%d-%s.leaf", dealer, digest),
	), nil
}

func (s *cvComponentShardStore) Put(sid string, epoch, dealer, holder int, leafDigest, artifact []byte) error {
	path, err := s.path(sid, epoch, dealer, holder, leafDigest)
	if err != nil {
		return err
	}
	return cvPutImmutableFile(path, artifact)
}

func (s *cvComponentShardStore) Read(sid string, epoch, dealer, holder int, leafDigest []byte) ([]byte, error) {
	path, err := s.path(sid, epoch, dealer, holder, leafDigest)
	if err != nil {
		return nil, err
	}
	return cvReadImmutableFile(path)
}

func (s *cvComponentShardStore) path(sid string, epoch, dealer, holder int, leafDigest []byte) (string, error) {
	if s == nil || dealer < 0 {
		return "", fmt.Errorf("invalid CV-sAPVSS component shard store key")
	}
	sidComponent, digest, err := cvStoreKeyParts(sid, epoch, holder, leafDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, sidComponent, fmt.Sprintf("epoch-%d", epoch), fmt.Sprintf("holder-%d", holder), fmt.Sprintf("dealer-%d-%s.shard", dealer, digest)), nil
}

func (s *cvFreshShardStore) Put(
	sid string,
	epoch int,
	headerDigest []byte,
	holder int,
	shard []byte,
) error {
	path, err := s.path(sid, epoch, headerDigest, holder)
	if err != nil {
		return err
	}
	return cvPutImmutableFile(path, shard)
}

func (s *cvFreshShardStore) Read(
	sid string,
	epoch int,
	headerDigest []byte,
	holder int,
) ([]byte, error) {
	path, err := s.path(sid, epoch, headerDigest, holder)
	if err != nil {
		return nil, err
	}
	return cvReadImmutableFile(path)
}

func (s *cvFreshShardStore) path(
	sid string,
	epoch int,
	headerDigest []byte,
	holder int,
) (string, error) {
	if s == nil {
		return "", fmt.Errorf("invalid CV-sAPVSS fresh-shard store")
	}
	sidComponent, digest, err := cvStoreKeyParts(sid, epoch, holder, headerDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(
		s.root,
		sidComponent,
		fmt.Sprintf("epoch-%d", epoch),
		fmt.Sprintf("holder-%d", holder),
		digest+".shard",
	), nil
}

func cvStoreKeyParts(sid string, epoch, holder int, digest []byte) (string, string, error) {
	if strings.TrimSpace(sid) == "" || epoch < 0 || holder < 0 || len(digest) != 32 {
		return "", "", fmt.Errorf("invalid CV-sAPVSS store key")
	}
	base := safeCacheComponent(sid)
	base = strings.Trim(base, "._-")
	if base == "" {
		base = "sid"
	}
	if len(base) > 64 {
		base = base[:64]
	}
	sidDigest := hashBytes([]byte("ARL-CV-sAPVSS/store-sid"), []byte(sid))
	return base + "-" + hex.EncodeToString(sidDigest), hex.EncodeToString(digest), nil
}

func cvEnsurePrivateStoreDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private CV-sAPVSS store directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("CV-sAPVSS store path is not a directory: %s", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect CV-sAPVSS store directory: %w", err)
	}
	return nil
}

func cvPutImmutableFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := cvEnsurePrivateStoreDir(dir); err != nil {
		return err
	}
	if existing, err := cvReadImmutableFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("CV-sAPVSS immutable store key already contains different bytes")
		}
		return cvSyncStoreDir(dir)
	} else if !os.IsNotExist(err) {
		return err
	}

	temporary, err := os.CreateTemp(dir, ".cv-write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		existing, readErr := cvReadImmutableFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("CV-sAPVSS immutable store key already contains different bytes")
		}
	}
	return cvSyncStoreDir(dir)
}

func cvReadImmutableFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("CV-sAPVSS store entry is not a private regular file: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func cvSyncStoreDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}
