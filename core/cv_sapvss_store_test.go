package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCVComponentLeafStoreIsImmutableIdempotentAndPrivate(t *testing.T) {
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("component leaf digest"))
	leaf := []byte("canonical Leaf")
	if err := store.Put("component-store", 4, 7, 2, digest, leaf); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("component-store", 4, 7, 2, digest, append([]byte(nil), leaf...)); err != nil {
		t.Fatalf("idempotent put: %v", err)
	}
	if err := store.Put("component-store", 4, 7, 2, digest, []byte("different Leaf")); err == nil {
		t.Fatal("same component key accepted different bytes")
	}

	got, err := store.Read("component-store", 4, 7, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, leaf) {
		t.Fatalf("stored leaf = %q, want %q", got, leaf)
	}
	got[0] ^= 0xff
	again, err := store.Read("component-store", 4, 7, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, leaf) {
		t.Fatal("component store read did not return an independent copy")
	}
	assertCVStoreModes(t, store.root, 1)
}

func TestCVFreshShardStoreIsImmutableIdempotentAndPrivate(t *testing.T) {
	store, err := newCVFreshShardStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	headerDigest := hashBytes([]byte("AggHeader digest"))
	shard := []byte("fresh RS shard and Merkle opening")
	if err := store.Put("shard-store", 8, headerDigest, 3, shard); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("shard-store", 8, headerDigest, 3, append([]byte(nil), shard...)); err != nil {
		t.Fatalf("idempotent put: %v", err)
	}
	if err := store.Put("shard-store", 8, headerDigest, 3, []byte("different shard")); err == nil {
		t.Fatal("same fresh-shard key accepted different bytes")
	}

	got, err := store.Read("shard-store", 8, headerDigest, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, shard) {
		t.Fatalf("stored shard = %q, want %q", got, shard)
	}
	got[0] ^= 0xff
	again, err := store.Read("shard-store", 8, headerDigest, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, shard) {
		t.Fatal("fresh shard store read did not return an independent copy")
	}
	assertCVStoreModes(t, store.root, 1)
}

func TestCVStoresKeepDistinctAndHostileSIDsInsideTheirRoots(t *testing.T) {
	base := t.TempDir()
	componentStore, err := newCVComponentLeafStore(base)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("shared digest"))
	if err := componentStore.Put("a/b", 1, 1, 1, digest, []byte("slash SID")); err != nil {
		t.Fatal(err)
	}
	if err := componentStore.Put("a_b", 1, 1, 1, digest, []byte("underscore SID")); err != nil {
		t.Fatalf("sanitized SID collision: %v", err)
	}
	for sid, want := range map[string][]byte{
		"a/b": []byte("slash SID"), "a_b": []byte("underscore SID"),
	} {
		got, err := componentStore.Read(sid, 1, 1, 1, digest)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read SID %q: got=%q err=%v", sid, got, err)
		}
	}
	if err := componentStore.Put("../../escape", 1, 2, 1, digest, []byte("contained")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hostile SID escaped store root: %v", err)
	}

	shardStore, err := newCVFreshShardStore(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := shardStore.Put("../../escape", 2, digest, 1, []byte("contained shard")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hostile SID escaped shard store root: %v", err)
	}
}

func TestCVStoresRejectInvalidKeys(t *testing.T) {
	componentStore, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shardStore, err := newCVFreshShardStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("valid digest"))
	shortDigest := digest[:len(digest)-1]
	componentCases := []struct {
		name                  string
		sid                   string
		epoch, dealer, holder int
		digest                []byte
	}{
		{name: "empty sid", sid: "", epoch: 1, dealer: 1, holder: 1, digest: digest},
		{name: "negative epoch", sid: "sid", epoch: -1, dealer: 1, holder: 1, digest: digest},
		{name: "negative dealer", sid: "sid", epoch: 1, dealer: -1, holder: 1, digest: digest},
		{name: "negative holder", sid: "sid", epoch: 1, dealer: 1, holder: -1, digest: digest},
		{name: "short digest", sid: "sid", epoch: 1, dealer: 1, holder: 1, digest: shortDigest},
	}
	for _, test := range componentCases {
		t.Run("component "+test.name, func(t *testing.T) {
			if err := componentStore.Put(test.sid, test.epoch, test.dealer, test.holder, test.digest, []byte("leaf")); err == nil {
				t.Fatal("accepted invalid component store key")
			}
			if _, err := componentStore.Read(test.sid, test.epoch, test.dealer, test.holder, test.digest); err == nil {
				t.Fatal("read accepted invalid component store key")
			}
		})
	}
	for _, test := range []struct {
		name          string
		sid           string
		epoch, holder int
		digest        []byte
	}{
		{name: "empty sid", sid: "", epoch: 1, holder: 1, digest: digest},
		{name: "negative epoch", sid: "sid", epoch: -1, holder: 1, digest: digest},
		{name: "negative holder", sid: "sid", epoch: 1, holder: -1, digest: digest},
		{name: "short digest", sid: "sid", epoch: 1, holder: 1, digest: shortDigest},
	} {
		t.Run("shard "+test.name, func(t *testing.T) {
			if err := shardStore.Put(test.sid, test.epoch, test.digest, test.holder, []byte("shard")); err == nil {
				t.Fatal("accepted invalid fresh-shard store key")
			}
			if _, err := shardStore.Read(test.sid, test.epoch, test.digest, test.holder); err == nil {
				t.Fatal("read accepted invalid fresh-shard store key")
			}
		})
	}
}

func TestCVFreshShardStoreConcurrentConflictDoesNotOverwrite(t *testing.T) {
	store, err := newCVFreshShardStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("concurrent header"))
	values := [][]byte{[]byte("first shard"), []byte("second shard")}
	errs := make([]error, len(values))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := range values {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errs[index] = store.Put("concurrent", 3, digest, 4, values[index])
		}(i)
	}
	close(start)
	wait.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent conflicting puts succeeded %d times, want 1; errors=%v", successes, errs)
	}
	got, err := store.Read("concurrent", 3, digest, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, values[0]) && !bytes.Equal(got, values[1]) {
		t.Fatalf("stored torn/unexpected shard: %q", got)
	}
}

func TestCVStoresRejectNonPrivateFiles(t *testing.T) {
	store, err := newCVFreshShardStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes([]byte("insecure existing shard"))
	path, err := store.path("permissions", 1, digest, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("same shard bytes")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("permissions", 1, digest, 2); err == nil {
		t.Fatal("read accepted a group/world-readable shard file")
	}
	if err := store.Put("permissions", 1, digest, 2, data); err == nil {
		t.Fatal("idempotent put accepted a group/world-readable shard file")
	}
}

func assertCVStoreModes(t *testing.T, root string, wantFiles int) {
	t.Helper()
	files := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if got := info.Mode().Perm(); got != 0o700 {
				t.Errorf("directory %s mode = %04o, want 0700", path, got)
			}
			return nil
		}
		files++
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("file %s mode = %04o, want 0600", path, got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files != wantFiles {
		t.Fatalf("stored file count = %d, want %d", files, wantFiles)
	}
}
