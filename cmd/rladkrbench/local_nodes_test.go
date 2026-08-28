package main

import (
	"os"
	"strings"
	"testing"
)

func TestReadLocalNodeIDsEnv(t *testing.T) {
	prev := os.Getenv("RLADKR_LOCAL_NODE_IDS")
	defer os.Setenv("RLADKR_LOCAL_NODE_IDS", prev)
	if err := os.Setenv("RLADKR_LOCAL_NODE_IDS", "3,1,3,9"); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	ids := readLocalNodeIDsEnv(4)
	if got, want := intsKey(ids), "1,3"; got != want {
		t.Fatalf("unexpected local ids: got=%s want=%s", got, want)
	}
}

func TestRequiredCompletedNodes_UsesLocalNodeSubsetWhenPresent(t *testing.T) {
	if got := requiredCompletedNodes(4, 1, []int{1, 3}); got != 2 {
		t.Fatalf("unexpected required completed count for local subset: got=%d want=2", got)
	}
	if got := requiredCompletedNodes(4, 1, nil); got != 3 {
		t.Fatalf("unexpected required completed count for full committee: got=%d want=3", got)
	}
}

func TestBenchResultIncludesLocalNodeMetrics(t *testing.T) {
	stats := []runStat{{
		latencyMs:         10,
		completedNodes:    2,
		decidedSetMean:    3,
		aggRLOReadyMs:     5,
		admitAggAttempts:  1,
		admitAggPasses:    1,
		recoverAggSuccess: 1,
	}}
	line := formatBenchResult(benchResultInput{
		n:                        4,
		fOld:                     1,
		fNew:                     1,
		kappa:                    2,
		runs:                     1,
		timeoutMs:                1000,
		apvssFallbackProfile:     "compact-batch",
		apvssForcedFallbackCount: 1,
		apvssWaitAllACKs:         false,
		experimentalAPVSS:        true,
		successRuns:              1,
		localNodes:               []int{1, 3},
		requiredCompleted:        2,
		stats:                    stats,
	})
	for _, token := range []string{
		"local_node_count=2",
		"required_completed_nodes=2",
		"apvss_fallback_profile=compact-batch",
		"apvss_forced_fallback_count=1",
		"apvss_wait_all_acks=false",
		"experimental_apvss=true",
	} {
		if !strings.Contains(line, token) {
			t.Fatalf("bench output missing token %q: %s", token, line)
		}
	}
}

func TestRequiredCompletedNodes_NeverExceedsGlobalNodeCount(t *testing.T) {
	if got := requiredCompletedNodes(1, 1, nil); got != 1 {
		t.Fatalf("unexpected required completed count at lower bound: got=%d want=1", got)
	}
}
