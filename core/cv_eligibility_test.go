package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVEligibilitySampleSize(t *testing.T) {
	c, err := cvEligibilitySampleSize(7, 2, 1, 100)
	if err != nil || c != 3 {
		t.Fatalf("sample size = %d, err=%v", c, err)
	}
	if _, err := cvEligibilitySampleSize(4, 4, 1, 100); err == nil {
		t.Fatal("accepted invalid f=n")
	}
}

func TestCVEligibilityCoinExchangeReturnsCommonProposerSet(t *testing.T) {
	cfg, leafContext, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(context.Background(), cfg, &leafContext, node, transport, router, store)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	type result struct {
		coin []byte
		err  error
	}
	results := make(chan result, len(services))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, service := range services {
		service := service
		go func() {
			coin, collectErr := service.CollectEligibilityCoin(ctx)
			results <- result{coin: coin, err: collectErr}
		}()
	}
	var wantCoin []byte
	var wantSet []int
	for range services {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		set, setErr := cvEligibilityProposerSet(nodes, cfg.FOld+1, cfg.FOld, got.coin)
		if setErr != nil {
			t.Fatal(setErr)
		}
		if wantCoin == nil {
			wantCoin = got.coin
			wantSet = set
			continue
		}
		if !bytes.Equal(wantCoin, got.coin) || len(set) != len(wantSet) {
			t.Fatalf("eligibility outputs disagree: coin=%t set=%v want=%v", bytes.Equal(wantCoin, got.coin), set, wantSet)
		}
		for i := range set {
			if set[i] != wantSet[i] {
				t.Fatalf("eligibility proposer sets disagree: %v != %v", set, wantSet)
			}
		}
	}
	if got, want := transport.sentCount(cvTagEligibilityShare), len(nodes)*(len(nodes)-1); got != want {
		t.Fatalf("eligibility shares sent=%d, want=%d", got, want)
	}
}

func TestCVEligibilityProposerSetCanonicalAndDomainSeparated(t *testing.T) {
	coin := cvEligibilityCoinInput("sid", 2)
	a, err := cvEligibilityProposerSet([]int{6, 2, 4, 0}, 2, 1, coin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cvEligibilityProposerSet([]int{0, 2, 4, 6}, 2, 1, coin)
	if err != nil || len(a) != 2 || a[0] != b[0] || a[1] != b[1] {
		t.Fatalf("non-canonical proposer set: %v %v", a, b)
	}
	if bytes.Equal(coin, cvEligibilityCoinInput("sid", 3)) {
		t.Fatal("eligibility coin input reused across epochs")
	}
	if _, err := cvEligibilityProposerSet([]int{0, 0, 1}, 1, 1, coin); err == nil {
		t.Fatal("accepted duplicate roster")
	}
}
