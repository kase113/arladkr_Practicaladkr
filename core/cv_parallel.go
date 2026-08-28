package core

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cvDefaultACKSettleGraceV2 = 250 * time.Millisecond

func cvACKSettleGraceV2() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RLADKR_ACK_SETTLE_GRACE_MS"))
	if raw == "" {
		return cvDefaultACKSettleGraceV2
	}
	milliseconds, err := strconv.Atoi(raw)
	if err != nil || milliseconds < 0 {
		return cvDefaultACKSettleGraceV2
	}
	if milliseconds > 250 {
		milliseconds = 250
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func cvLeafVerifyWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	// Inner MSM work is already single-threaded. Use the whole outer budget:
	// four vCPUs on c7g.xlarge and up to eight on 2xlarge-class nodes so
	// n>=128 catalogs are not serialized behind the old four-worker cap.
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_LEAF_VERIFY_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 8 {
		workers = 8
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvLeafBuildWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_LEAF_BUILD_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 4 {
		workers = 4
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvComponentRecoveryWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0) * 2
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_RECOVERY_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 16 {
		workers = 16
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvCryptoWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	// Keep one scheduler slot available for the authenticated transport, MVBA,
	// and timers on a multi-core node. A deployment can override this budget
	// explicitly after profiling its own CPU topology.
	if workers > 1 {
		workers--
	}
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_CRYPTO_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 4 {
		workers = 4
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvRSWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > 1 {
		workers--
	}
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_RS_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 4 {
		workers = 4
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvNetworkWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_SEND_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 8 {
		workers = 8
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvLaneWorkers(jobs int) int {
	workers := cvCryptoWorkers(jobs)
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_LANE_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 4 {
		workers = 4
	}
	if workers > jobs {
		workers = jobs
	}
	return workers
}

// cvNestedMSMWorkers is used inside work that is already parallelized across
// leaves or lanes. Keeping the inner MSM serial prevents multiplicative
// goroutine fan-out while preserving the exact group equation.
func cvNestedMSMWorkers(points int) int {
	if points <= 0 {
		return 0
	}
	return 1
}

// cvRunParallelChecks preserves deterministic error selection while bounding
// the number of concurrent cryptographic jobs per process.
func cvRunParallelChecks(jobs int, check func(int) error) error {
	if jobs <= 0 {
		return nil
	}
	workers := cvCryptoWorkers(jobs)
	if workers == 1 {
		for index := 0; index < jobs; index++ {
			if err := check(index); err != nil {
				return err
			}
		}
		return nil
	}
	errs := make([]error, jobs)
	indices := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range indices {
				errs[index] = check(index)
			}
		}()
	}
	for index := 0; index < jobs; index++ {
		indices <- index
	}
	close(indices)
	group.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// cvLoadVerifiedLeavesOrdered bounds concurrent retrieval/verification while
// retaining descriptor order. Callers that require every leaf can therefore
// report the lowest-index failure deterministically; FirstKValid callers may
// skip failures without making completion order part of selection.
func cvLoadVerifiedLeavesOrdered(
	ctx context.Context,
	descriptors []*cvComponentDescriptor,
	load func(context.Context, *cvComponentDescriptor) (*cvVerifiedLeaf, error),
) ([]*cvVerifiedLeaf, []error) {
	leaves := make([]*cvVerifiedLeaf, len(descriptors))
	errs := make([]error, len(descriptors))
	if len(descriptors) == 0 {
		return leaves, errs
	}
	workers := cvLeafVerifyWorkers(len(descriptors))
	if workers == 1 {
		for index, descriptor := range descriptors {
			leaves[index], errs[index] = load(ctx, descriptor)
		}
		return leaves, errs
	}
	jobs := make(chan int, len(descriptors))
	for index := range descriptors {
		jobs <- index
	}
	close(jobs)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				leaves[index], errs[index] = load(ctx, descriptors[index])
			}
		}()
	}
	group.Wait()
	return leaves, errs
}

func cvFirstOrderedError(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
