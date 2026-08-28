package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"practical_adkr/core"
)

func TestPracticalResultDigestIsCanonicalAndContextBound(t *testing.T) {
	cfg := core.Config{SID: "sid", Epoch: 3}
	result := &core.Result{
		DecidedSet: []int{2, 0, 1}, SelectedTranscripts: []int{2, 1},
		NewThresholdPK: []byte("pk"), CoinSignature: []byte("coin"),
	}
	first, err := practicalResultDigest(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	result.DecidedSet = []int{1, 2, 0}
	result.SelectedTranscripts = []int{1, 2}
	second, err := practicalResultDigest(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("canonical result digest depends on set ordering")
	}
	cfg.Epoch++
	third, err := practicalResultDigest(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("result digest is not bound to the epoch")
	}
}

func TestBenchmarkEpochBarrierWaitsForAllAndRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	committee := []int{0, 1}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for _, id := range committee {
		id := id
		go func() {
			errs <- waitForBenchmarkEpoch(ctx, dir, "sid", 1, 7, committee, []int{id}, "same")
		}()
	}
	for range committee {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	mismatchDir := t.TempDir()
	mismatchCtx, mismatchCancel := context.WithTimeout(context.Background(), time.Second)
	defer mismatchCancel()
	go func() {
		errs <- waitForBenchmarkEpoch(mismatchCtx, mismatchDir, "sid", 1, 8, committee, []int{0}, "same")
	}()
	go func() {
		errs <- waitForBenchmarkEpoch(mismatchCtx, mismatchDir, "sid", 1, 8, committee, []int{1}, "other")
	}()
	mismatchSeen := false
	for range committee {
		if err := <-errs; err != nil && strings.Contains(err.Error(), "result mismatch") {
			mismatchSeen = true
		}
	}
	if !mismatchSeen {
		t.Fatal("mismatched result was not rejected")
	}
}
