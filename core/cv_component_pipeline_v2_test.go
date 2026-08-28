package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cvComponentPipelineTestRefsV2(count int) []cvComponentRefV2 {
	refs := make([]cvComponentRefV2, count)
	for index := range refs {
		refs[index].Header.DealerID = index
	}
	return refs
}

func TestCVComponentPipelineVerifiesBeforeAllRecoveryCompletes(t *testing.T) {
	refs := cvComponentPipelineTestRefsV2(8)
	releaseRecovery := make(chan struct{})
	verificationStarted := make(chan struct{})
	var signalOnce sync.Once
	done := make(chan []cvComponentVerificationResultV2, 1)

	go func() {
		results, _ := cvRunComponentPipelineV2(
			refs, 4, 4,
			func(ref cvComponentRefV2) cvComponentVerificationResultV2 {
				if ref.Header.DealerID != 0 {
					<-releaseRecovery
				}
				return cvComponentVerificationResultV2{ref: ref}
			},
			func(result cvComponentVerificationResultV2) cvComponentVerificationResultV2 {
				signalOnce.Do(func() { close(verificationStarted) })
				return result
			},
		)
		done <- results
	}()

	select {
	case <-verificationStarted:
	case <-time.After(time.Second):
		close(releaseRecovery)
		t.Fatal("verification waited for the recovery batch to complete")
	}
	close(releaseRecovery)
	select {
	case results := <-done:
		if len(results) != len(refs) {
			t.Fatalf("pipeline results=%d, want %d", len(results), len(refs))
		}
		for index := range results {
			if results[index].ref.Header.DealerID != index {
				t.Fatalf("pipeline result %d has dealer %d", index, results[index].ref.Header.DealerID)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("component pipeline did not finish")
	}
}

func TestCVComponentPipelineBoundsVerifierConcurrency(t *testing.T) {
	refs := cvComponentPipelineTestRefsV2(12)
	releaseVerification := make(chan struct{})
	fourActive := make(chan struct{})
	var fourActiveOnce sync.Once
	var active atomic.Int32
	var maximum atomic.Int32
	done := make(chan struct{})

	go func() {
		defer close(done)
		cvRunComponentPipelineV2(
			refs, 8, 4,
			func(ref cvComponentRefV2) cvComponentVerificationResultV2 {
				return cvComponentVerificationResultV2{ref: ref}
			},
			func(result cvComponentVerificationResultV2) cvComponentVerificationResultV2 {
				current := active.Add(1)
				for {
					observed := maximum.Load()
					if current <= observed || maximum.CompareAndSwap(observed, current) {
						break
					}
				}
				if current == 4 {
					fourActiveOnce.Do(func() { close(fourActive) })
				}
				<-releaseVerification
				active.Add(-1)
				return result
			},
		)
	}()

	select {
	case <-fourActive:
	case <-time.After(time.Second):
		close(releaseVerification)
		t.Fatal("four verifier workers did not become active")
	}
	if got := maximum.Load(); got != 4 {
		close(releaseVerification)
		t.Fatalf("maximum verifier concurrency=%d, want 4", got)
	}
	close(releaseVerification)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bounded verifier pipeline did not finish")
	}
}
