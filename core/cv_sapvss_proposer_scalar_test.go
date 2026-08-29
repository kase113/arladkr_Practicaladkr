package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCVSampledProposerSlotsScalarSilentFirstProposerDoesNotBlock(t *testing.T) {
	t.Setenv("RLADKR_CV_PRIMARY_GRACE_MS", "0")
	proposers := []int{3, 7, 11}
	candidate := &cvAgreementObjectScalar{Header: cvAggregateHeaderScalar{ProposerID: proposers[1]}}
	candidates := make(chan *cvAgreementObjectScalar, 1)
	started := make(chan int, len(proposers))
	canceled := make(chan int, len(proposers))
	var publishOnce sync.Once

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan struct {
		candidate *cvAgreementObjectScalar
		err       error
	}, 1)
	go func() {
		got, err := cvRunSampledProposerSlotsScalar(ctx, proposers, candidates, func(slotCtx context.Context, proposer int) error {
			started <- proposer
			switch proposer {
			case proposers[0]:
				<-slotCtx.Done()
				canceled <- proposer
				return slotCtx.Err()
			case proposers[1]:
				publishOnce.Do(func() { candidates <- candidate })
				<-slotCtx.Done()
				canceled <- proposer
				return slotCtx.Err()
			default:
				return errors.New("independent proposer slot failure")
			}
		})
		result <- struct {
			candidate *cvAgreementObjectScalar
			err       error
		}{candidate: got, err: err}
	}()

	seen := make(map[int]struct{}, len(proposers))
	for range proposers {
		select {
		case proposer := <-started:
			seen[proposer] = struct{}{}
		case <-ctx.Done():
			t.Fatal("not all sampled proposer slots started")
		}
	}
	if len(seen) != len(proposers) {
		t.Fatalf("started proposer slots=%v", seen)
	}
	select {
	case got := <-result:
		if got.err != nil || got.candidate != candidate {
			t.Fatalf("candidate=%p want=%p err=%v", got.candidate, candidate, got.err)
		}
	case <-ctx.Done():
		t.Fatal("silent first proposer blocked another sampled proposer")
	}
	for i := 0; i < 2; i++ {
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("unfinished proposer slot was not canceled after first candidate")
		}
	}
}

func TestCVSampledProposerSlotsScalarStagesBackupsUntilPrimaryGrace(t *testing.T) {
	t.Setenv("RLADKR_CV_PROPOSER_SLOT_GRACE_MS", "80")
	proposers := []int{3, 7}
	candidate := &cvAgreementObjectScalar{Header: cvAggregateHeaderScalar{ProposerID: proposers[1]}}
	candidates := make(chan *cvAgreementObjectScalar, 1)
	started := make(chan int, len(proposers))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result := make(chan *cvAgreementObjectScalar, 1)
	go func() {
		got, _ := cvRunSampledProposerSlotsScalar(ctx, proposers, candidates, func(slotCtx context.Context, proposer int) error {
			started <- proposer
			if proposer == proposers[1] {
				candidates <- candidate
			}
			<-slotCtx.Done()
			return slotCtx.Err()
		})
		result <- got
	}()

	if proposer := <-started; proposer != proposers[0] {
		t.Fatalf("first slot=%d want primary=%d", proposer, proposers[0])
	}
	select {
	case proposer := <-started:
		t.Fatalf("backup %d started before primary grace", proposer)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case proposer := <-started:
		if proposer != proposers[1] {
			t.Fatalf("backup slot=%d want=%d", proposer, proposers[1])
		}
	case <-ctx.Done():
		t.Fatal("backup did not start after primary grace")
	}
	select {
	case got := <-result:
		if got != candidate {
			t.Fatalf("candidate=%p want=%p", got, candidate)
		}
	case <-ctx.Done():
		t.Fatal("backup candidate did not complete staged proposer slots")
	}
}

func TestCVSampledProposerSlotGraceScalarDefaultsBySampleSize(t *testing.T) {
	t.Setenv("RLADKR_CV_PROPOSER_SLOT_GRACE_MS", "")
	t.Setenv("RLADKR_CV_PRIMARY_GRACE_MS", "10000")
	if got := cvSampledProposerSlotGraceScalar(6); got != 10*time.Second {
		t.Fatalf("small-sample proposer grace=%s", got)
	}
	if got := cvSampledProposerSlotGraceScalar(11); got != 0 {
		t.Fatalf("large-sample proposer grace=%s", got)
	}
	t.Setenv("RLADKR_CV_PROPOSER_SLOT_GRACE_MS", "125")
	if got := cvSampledProposerSlotGraceScalar(11); got != 125*time.Millisecond {
		t.Fatalf("explicit large-sample proposer grace=%s", got)
	}
}

func TestCVSampledProposerSlotsScalarFailsOnlyAfterEverySlotFails(t *testing.T) {
	proposers := []int{2, 4, 6}
	candidates := make(chan *cvAgreementObjectScalar, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := cvRunSampledProposerSlotsScalar(ctx, proposers, candidates, func(context.Context, int) error {
		return errors.New("slot failed")
	})
	if err == nil || err.Error() != "all sampled CV V2 proposer slots failed" {
		t.Fatalf("all-slot failure error=%v", err)
	}
}
