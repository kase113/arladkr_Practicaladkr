package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"rladkr_go/core"
)

func TestARLResultDigestIsCanonicalAndContextBound(t *testing.T) {
	cfg := core.Config{SID: "sid", Epoch: 3}
	result := &core.EpochResult{
		LockedSet: []int{2, 0, 1}, AggRLODigest: []byte("rlo"),
		RecoveredAggregate: []byte("aggregate"), NewPublicKey: []byte("pk"),
	}
	first, err := arlResultDigest(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	result.LockedSet = []int{1, 2, 0}
	second, err := arlResultDigest(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("canonical result digest depends on set ordering")
	}
	cfg.Epoch++
	third, err := arlResultDigest(cfg, result)
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

func TestBenchmarkEpochBarrierAcceptsQuorum(t *testing.T) {
	dir := t.TempDir()
	committee := []int{0, 1, 2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for _, id := range []int{0, 2} {
		id := id
		go func() {
			errs <- waitForBenchmarkEpochQuorum(ctx, dir, "sid", 1, 1, committee, []int{id}, "same", 2)
		}()
	}
	for range []int{0, 2} {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
