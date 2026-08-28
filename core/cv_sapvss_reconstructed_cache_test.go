package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type cvRecordedLeafCacheWrite struct {
	dealer     int
	holder     int
	leafDigest []byte
	leafWire   []byte
}

type cvRecordingLeafCacheStore struct {
	writes chan cvRecordedLeafCacheWrite
	putErr error
}

func (s *cvRecordingLeafCacheStore) Put(
	_ string,
	_ int,
	dealer int,
	holder int,
	leafDigest, leafWire []byte,
) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.writes <- cvRecordedLeafCacheWrite{
		dealer: dealer, holder: holder, leafDigest: append([]byte(nil), leafDigest...),
		leafWire: append([]byte(nil), leafWire...),
	}
	return nil
}

func (*cvRecordingLeafCacheStore) Read(string, int, int, int, []byte) ([]byte, error) {
	return nil, os.ErrNotExist
}

func TestCVReconstructedLeafCacheModes(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{raw: "", want: "async"},
		{raw: "async", want: "async"},
		{raw: "sync", want: "sync"},
		{raw: "off", want: "off"},
		{raw: "invalid", want: "async"},
	} {
		t.Setenv("RLADKR_RECONSTRUCTED_LEAF_CACHE_MODE", test.raw)
		if got := cvReconstructedLeafCacheMode(); got != test.want {
			t.Fatalf("cache mode %q produced %q, want %q", test.raw, got, test.want)
		}
	}
	t.Setenv("RLADKR_RECONSTRUCTED_LEAF_CACHE_QUEUE", "7")
	if got := cvReconstructedLeafCacheQueueCapacity(); got != 7 {
		t.Fatalf("cache queue capacity=%d, want 7", got)
	}
	t.Setenv("RLADKR_RECONSTRUCTED_LEAF_CACHE_QUEUE", "1000")
	if got := cvReconstructedLeafCacheQueueCapacity(); got != 2 {
		t.Fatalf("unbounded cache queue was not reset to default: %d", got)
	}
}

func TestCVReconstructedLeafAsyncCacheCopiesAndPersists(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &cvRecordingLeafCacheStore{writes: make(chan cvRecordedLeafCacheWrite, 1)}
	service := &cvComponentService{
		ctx: ctx, cfg: Config{SID: "async-cache", Epoch: 3}, localNode: 5, store: store,
		reconstructedCacheMode: "async", reconstructedCacheQueue: make(chan cvReconstructedLeafCacheJob, 1),
	}
	service.backgroundWG.Add(1)
	go service.runReconstructedLeafCacheWriter()
	leafWire := []byte("verified reconstructed leaf")
	digest := cvComponentLeafPayloadDigest(leafWire)
	if err := service.cacheReconstructedLeaf(2, digest, leafWire); err != nil {
		t.Fatal(err)
	}
	leafWire[0] ^= 1
	digest[0] ^= 1
	select {
	case write := <-store.writes:
		if write.dealer != 2 || write.holder != 5 ||
			!bytes.Equal(write.leafWire, []byte("verified reconstructed leaf")) ||
			!bytes.Equal(write.leafDigest, cvComponentLeafPayloadDigest(write.leafWire)) {
			t.Fatalf("async cache did not own an immutable job copy: %+v", write)
		}
	case <-time.After(time.Second):
		t.Fatal("async reconstructed-leaf cache did not write")
	}
	cancel()
	done := make(chan struct{})
	go func() {
		service.backgroundWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("async reconstructed-leaf cache worker did not stop")
	}
}

func TestCVReconstructedLeafCacheIsBoundedAndSyncErrorsPropagate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan cvReconstructedLeafCacheJob, 1)
	service := &cvComponentService{
		ctx: ctx, cfg: Config{SID: "bounded-cache", Epoch: 4}, localNode: 6,
		store:                  &cvRecordingLeafCacheStore{writes: make(chan cvRecordedLeafCacheWrite, 1)},
		reconstructedCacheMode: "async", reconstructedCacheQueue: queue,
	}
	first := []byte("first verified leaf")
	second := []byte("second verified leaf")
	if err := service.cacheReconstructedLeaf(1, cvComponentLeafPayloadDigest(first), first); err != nil {
		t.Fatal(err)
	}
	if err := service.cacheReconstructedLeaf(2, cvComponentLeafPayloadDigest(second), second); err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 {
		t.Fatalf("bounded cache retained %d jobs, want 1", len(queue))
	}
	job := <-queue
	if job.dealer != 1 || !bytes.Equal(job.leafWire, first) {
		t.Fatal("bounded cache did not retain the first queued job")
	}

	injected := errors.New("injected reconstructed-cache failure")
	service.reconstructedCacheMode = "sync"
	service.store = &cvRecordingLeafCacheStore{
		writes: make(chan cvRecordedLeafCacheWrite, 1), putErr: injected,
	}
	if err := service.cacheReconstructedLeaf(1, cvComponentLeafPayloadDigest(first), first); !errors.Is(err, injected) {
		t.Fatalf("sync cache error=%v, want injected failure", err)
	}
}
