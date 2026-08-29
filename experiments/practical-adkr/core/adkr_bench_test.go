package core

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Keep fixed listeners outside Linux's ephemeral port range (typically
// 32768-60999); APDB reply listeners intentionally bind to :0.
var benchPortBase uint32 = 20000

func nextBenchBase(span int) int {
	return int(atomic.AddUint32(&benchPortBase, uint32(span)))
}

func buildNodeAddrCSV(ids []int, base int) string {
	parts := make([]string, 0, len(ids))
	for i, id := range ids {
		parts = append(parts, fmt.Sprintf("%d=127.0.0.1:%d", id, base+i))
	}
	return strings.Join(parts, ",")
}

func buildNodeIDsCSV(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ",")
}

// BenchmarkPracticalADKR benchmarks the full ADKR protocol for various n/f.
func BenchmarkPracticalADKR(b *testing.B) {
	configurations := []struct {
		n, f, kappa int
	}{
		{4, 1, 2},
		{7, 2, 3},
		{10, 3, 4},
	}

	for _, tc := range configurations {
		name := fmt.Sprintf("n=%d_f=%d_k=%d", tc.n, tc.f, tc.kappa)
		b.Run(name, func(b *testing.B) {
			old := make([]int, tc.n)
			newC := make([]int, tc.n)
			for i := 0; i < tc.n; i++ {
				old[i] = i
				newC[i] = 100 + i
			}
			cfg := Config{
				SID:                  "bench-adkr",
				OldCommittee:         old,
				NewCommittee:         newC,
				F:                    tc.f,
				Kappa:                tc.kappa,
				PaillierBits:         2048,
				MVBANodeAddrs:        buildNodeAddrCSV(old, 35000),
				MVBALocalNodeIDs:     buildNodeIDsCSV(old),
				ProtocolNodeAddrs:    buildNodeAddrCSV(append(append([]int(nil), old...), newC...), 36000),
				ProtocolLocalNodeIDs: buildNodeIDsCSV(append(append([]int(nil), old...), newC...)),
			}
			ctx := context.Background()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				iterCfg := cfg
				runBase := nextBenchBase(400)
				iterCfg.MVBANodeAddrs = buildNodeAddrCSV(old, runBase)
				iterCfg.ProtocolNodeAddrs = buildNodeAddrCSV(append(append([]int(nil), old...), newC...), runBase+100)
				iterCfg.CompNodeAddrs = buildNodeAddrCSV(newC, runBase+200)
				_, err := RunPracticalADKR(ctx, iterCfg)
				if err != nil {
					b.Fatalf("ADKR failed: %v", err)
				}
			}
		})
	}
}

// TestBenchmarkCostReport prints a human-readable cost report.
func TestBenchmarkCostReport(t *testing.T) {
	configs := []struct {
		label       string
		n, f, kappa int
	}{
		{"Small (n=4,f=1,κ=2)", 4, 1, 2},
		{"Medium (n=7,f=2,κ=3)", 7, 2, 3},
	}

	for _, tc := range configs {
		old := make([]int, tc.n)
		newC := make([]int, tc.n)
		for i := 0; i < tc.n; i++ {
			old[i] = i
			newC[i] = 100 + i
		}
		baseCfg := Config{
			SID:                  "bench-cost",
			OldCommittee:         old,
			NewCommittee:         newC,
			F:                    tc.f,
			Kappa:                tc.kappa,
			PaillierBits:         2048,
			MVBANodeAddrs:        buildNodeAddrCSV(old, 37000),
			MVBALocalNodeIDs:     buildNodeIDsCSV(old),
			ProtocolNodeAddrs:    buildNodeAddrCSV(append(append([]int(nil), old...), newC...), 38000),
			ProtocolLocalNodeIDs: buildNodeIDsCSV(append(append([]int(nil), old...), newC...)),
		}
		ctx := context.Background()

		runs := 3
		var totalDuration time.Duration
		for i := 0; i < runs; i++ {
			cfg := baseCfg
			runBase := nextBenchBase(400)
			cfg.MVBANodeAddrs = buildNodeAddrCSV(old, runBase)
			cfg.ProtocolNodeAddrs = buildNodeAddrCSV(append(append([]int(nil), old...), newC...), runBase+100)
			cfg.CompNodeAddrs = buildNodeAddrCSV(newC, runBase+200)
			start := time.Now()
			result, err := RunPracticalADKR(ctx, cfg)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("[%s] run %d failed: %v", tc.label, i, err)
			}
			totalDuration += elapsed
			_ = result
		}
		avg := totalDuration / time.Duration(runs)

		t.Logf("=== %s ===", tc.label)
		t.Logf("  Avg total:  %v", avg)
		t.Logf("  Per dealer: ~%v", avg/time.Duration(tc.n))
	}
}

func TestPartialVerifyN7Comparison(t *testing.T) {
	old := make([]int, 7)
	newC := make([]int, 7)
	for i := range old {
		old[i] = i
		newC[i] = 100 + i
	}
	run := func(mode string, base int) *Result {
		cfg := Config{
			SID:                  "partial-verify-n7-comparison-" + mode,
			OldCommittee:         old,
			NewCommittee:         newC,
			F:                    2,
			Kappa:                3,
			PaillierBits:         2048,
			MVBANetwork:          "tcp",
			MVBANodeAddrs:        buildNodeAddrCSV(old, base),
			MVBALocalNodeIDs:     buildNodeIDsCSV(old),
			ProtocolNodeAddrs:    buildNodeAddrCSV(append(append([]int(nil), old...), newC...), base+100),
			ProtocolLocalNodeIDs: buildNodeIDsCSV(append(append([]int(nil), old...), newC...)),
			CompNodeAddrs:        buildNodeAddrCSV(newC, base+200),
			AblationMode:         mode,
			CommMetrics:          true,
		}
		result, err := RunPracticalADKR(context.Background(), cfg)
		if err != nil {
			t.Fatalf("mode=%s: %v", mode, err)
		}
		return result
	}

	full := run("full-local-verify", nextBenchBase(500))
	multicast := run("none", nextBenchBase(500))
	t.Logf("n=7 f=2 kappa=3 full-local mode=%s partial_verify_ms=%.3f sent=%d recv=%d",
		full.PartialVerifyMode,
		float64(full.PhaseTimings["partial_verify"].Microseconds())/1000,
		full.PhaseSentBytes["partial_verify"], full.PhaseRecvBytes["partial_verify"])
	t.Logf("n=7 f=2 kappa=3 multicast mode=%s partial_verify_ms=%.3f sent=%d recv=%d votes=%v",
		multicast.PartialVerifyMode,
		float64(multicast.PhaseTimings["partial_verify"].Microseconds())/1000,
		multicast.PhaseSentBytes["partial_verify"], multicast.PhaseRecvBytes["partial_verify"],
		multicast.PartialVerifyPositiveVotes)
	if multicast.PartialVerifyMode != "result-multicast" {
		t.Fatalf("multicast run used mode %q", multicast.PartialVerifyMode)
	}
	if len(multicast.PartialVerifyPositiveVotes) != 21 {
		t.Fatalf("positive vote entries=%d, want 21", len(multicast.PartialVerifyPositiveVotes))
	}
	for key, votes := range multicast.PartialVerifyPositiveVotes {
		if votes < 3 {
			t.Fatalf("lane %s positive votes=%d, want >=3", key, votes)
		}
	}
}
