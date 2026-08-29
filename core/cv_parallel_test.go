package core

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestCVCryptoWorkerBudget(t *testing.T) {
	t.Setenv("RLADKR_CRYPTO_WORKERS", "3")
	if got := cvCryptoWorkers(10); got != 3 {
		t.Fatalf("configured crypto workers=%d, want 3", got)
	}
	if got := cvCryptoWorkers(2); got != 2 {
		t.Fatalf("job-limited crypto workers=%d, want 2", got)
	}
	t.Setenv("RLADKR_CRYPTO_WORKERS", "99")
	if got := cvCryptoWorkers(10); got != 4 {
		t.Fatalf("capped crypto workers=%d, want 4", got)
	}
	if got := cvNestedMSMWorkers(64); got != 1 {
		t.Fatalf("nested MSM workers=%d, want 1", got)
	}
	t.Setenv("RLADKR_RS_WORKERS", "2")
	if got := cvRSWorkers(10); got != 2 {
		t.Fatalf("configured RS workers=%d, want 2", got)
	}
}

func TestCVLeafVerifyWorkerBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	t.Setenv("RLADKR_LEAF_VERIFY_WORKERS", "")
	if got := cvLeafVerifyWorkers(22); got != 4 {
		t.Fatalf("four-vCPU leaf verification workers=%d, want 4", got)
	}
	t.Setenv("RLADKR_LEAF_VERIFY_WORKERS", "4")
	if got := cvLeafVerifyWorkers(10); got != 4 {
		t.Fatalf("configured leaf verification workers=%d, want 4", got)
	}
	if got := cvLeafVerifyWorkers(2); got != 2 {
		t.Fatalf("job-limited leaf verification workers=%d, want 2", got)
	}
	t.Setenv("RLADKR_LEAF_VERIFY_WORKERS", "99")
	if got := cvLeafVerifyWorkers(10); got != 8 {
		t.Fatalf("capped leaf verification workers=%d, want 8", got)
	}
}

func TestCVComponentRecoveryWorkerBudget(t *testing.T) {
	t.Setenv("RLADKR_COMPONENT_RECOVERY_WORKERS", "8")
	if got := cvComponentRecoveryWorkers(22); got != 8 {
		t.Fatalf("configured component recovery workers=%d, want 8", got)
	}
	if got := cvComponentRecoveryWorkers(3); got != 3 {
		t.Fatalf("job-limited component recovery workers=%d, want 3", got)
	}
	t.Setenv("RLADKR_COMPONENT_RECOVERY_WORKERS", "99")
	if got := cvComponentRecoveryWorkers(22); got != 16 {
		t.Fatalf("capped component recovery workers=%d, want 16", got)
	}
}

func TestCVRecoveryServiceWorkerBudget(t *testing.T) {
	t.Setenv("RLADKR_APDB_RECOVERY_WORKERS", "")
	if got := cvRecoveryServiceWorkers(4); got != 2 {
		t.Fatalf("small recovery service workers=%d, want 2", got)
	}
	if got := cvRecoveryServiceWorkers(96); got != 6 {
		t.Fatalf("committee recovery service workers=%d, want 6", got)
	}
	t.Setenv("RLADKR_APDB_RECOVERY_WORKERS", "12")
	if got := cvRecoveryServiceWorkers(96); got != 12 {
		t.Fatalf("configured recovery service workers=%d, want 12", got)
	}
	t.Setenv("RLADKR_APDB_RECOVERY_WORKERS", "99")
	if got := cvRecoveryServiceWorkers(96); got != 16 {
		t.Fatalf("capped recovery service workers=%d, want 16", got)
	}
}

func TestCVACKSettleGraceScalarIsBoundedAndConfigurable(t *testing.T) {
	t.Setenv("RLADKR_ACK_SETTLE_GRACE_MS", "")
	if got := cvACKSettleGraceScalar(); got != cvDefaultACKSettleGraceScalar {
		t.Fatalf("default ACK settle grace=%s, want %s", got, cvDefaultACKSettleGraceScalar)
	}
	t.Setenv("RLADKR_ACK_SETTLE_GRACE_MS", "0")
	if got := cvACKSettleGraceScalar(); got != 0 {
		t.Fatalf("disabled ACK settle grace=%s", got)
	}
	t.Setenv("RLADKR_ACK_SETTLE_GRACE_MS", "1000")
	if got := cvACKSettleGraceScalar(); got != 250*time.Millisecond {
		t.Fatalf("capped ACK settle grace=%s, want 250ms", got)
	}
}

func TestCVLoadVerifiedLeavesOrderedAndBounded(t *testing.T) {
	t.Setenv("RLADKR_LEAF_VERIFY_WORKERS", "2")
	descriptors := make([]*cvComponentDescriptor, 6)
	for index := range descriptors {
		descriptors[index] = &cvComponentDescriptor{dealer: index}
	}
	var active atomic.Int32
	var peak atomic.Int32
	loaded, errs := cvLoadVerifiedLeavesOrdered(context.Background(), descriptors,
		func(_ context.Context, descriptor *cvComponentDescriptor) (*cvVerifiedLeaf, error) {
			current := active.Add(1)
			for {
				old := peak.Load()
				if current <= old || peak.CompareAndSwap(old, current) {
					break
				}
			}
			defer active.Add(-1)
			time.Sleep(time.Duration(len(descriptors)-descriptor.dealer) * time.Millisecond)
			if descriptor.dealer == 1 || descriptor.dealer == 4 {
				return nil, fmt.Errorf("dealer %d", descriptor.dealer)
			}
			return &cvVerifiedLeaf{leafDigest: []byte{byte(descriptor.dealer)}}, nil
		})
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak concurrent leaf loads=%d, want 2", got)
	}
	for index := range descriptors {
		if index == 1 || index == 4 {
			if errs[index] == nil || loaded[index] != nil {
				t.Fatalf("missing ordered failure at index %d", index)
			}
			continue
		}
		if errs[index] != nil || loaded[index] == nil || len(loaded[index].leafDigest) != 1 || int(loaded[index].leafDigest[0]) != index {
			t.Fatalf("ordered result %d does not match descriptor", index)
		}
	}
	if got := cvFirstOrderedError(errs); got == nil || got.Error() != "dealer 1" {
		t.Fatalf("first deterministic error=%v, want dealer 1", got)
	}
}

func TestCVLaneWorkerBudgetHasIndependentOverride(t *testing.T) {
	t.Setenv("RLADKR_CRYPTO_WORKERS", "1")
	t.Setenv("RLADKR_LANE_WORKERS", "3")
	if got := cvLaneWorkers(8); got != 3 {
		t.Fatalf("lane workers=%d, want 3", got)
	}
	if got := cvLaneWorkers(2); got != 2 {
		t.Fatalf("bounded lane workers=%d, want 2", got)
	}
}
