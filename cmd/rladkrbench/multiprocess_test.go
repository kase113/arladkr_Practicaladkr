package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"rladkr_go/core"
)

func TestBenchMultiProcessSingleMVBA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multiprocess CV V2 benchmark in short mode")
	}
	results := runBenchProcesses(t)
	if len(results) != 2 {
		t.Fatalf("expected 2 bench results, got=%d", len(results))
	}
	for _, line := range results {
		for _, token := range []string{
			"success_runs=1",
			"local_node_count=1",
			"required_completed_nodes=1",
			"agreement_path=single-mvba-v2",
			"cv_apvss_mode=cv-sapvss-v2-scalar-group",
			"arc_mode=v2-apdb-aggregate-lock",
		} {
			if !strings.Contains(line, token) {
				t.Fatalf("legacy-off bench output missing token %q: %s", token, line)
			}
		}
	}
}

func TestBenchMultiProcessFourNodePrivateStyleSubsets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multiprocess CV V2 benchmark in short mode")
	}
	results := runBenchProcessesDetailedWithTopology(t, benchProcessTopology{
		n:       4,
		f:       1,
		kappa:   2,
		timeout: 45 * time.Second,
		localNodeSets: [][]int{
			{0},
			{1},
			{2},
			{3},
		},
	})
	if len(results) != 4 {
		t.Fatalf("expected 4 bench responses, got=%d", len(results))
	}
	metricTotals := make(map[string]float64)
	for _, res := range results {
		line := extractBenchLine(t, res.stdout)
		if strings.TrimSpace(res.stderr) != "" {
			t.Logf("four-node force stderr:\n%s", res.stderr)
		}
		for _, token := range []string{
			"success_runs=1",
			"local_node_count=1",
			"required_completed_nodes=1",
			"agreement_path=single-mvba-v2",
			"cv_apvss_mode=cv-sapvss-v2-scalar-group",
			"arc_mode=v2-apdb-aggregate-lock",
		} {
			if !strings.Contains(line, token) {
				t.Fatalf("four-node force bench output missing token %q: %s", token, line)
			}
		}
		for _, field := range []string{
			"mean_total_sent_bytes", "mean_apvss_ack_count", "mean_apvss_proof_bytes",
			"mean_apvss_leaf_wire_bytes", "mean_candidate_formation_sent_bytes",
			"mean_aggregate_agreement_sent_bytes", "mean_completed_candidate_count",
			"mean_pool_wire_bytes", "mean_validation_request_wire_bytes", "mean_agreement_object_wire_bytes",
			"mean_aggregate_payload_bytes", "mean_aggregate_apdb_encoded_bytes",
			"mean_pool_certificate_bytes", "mean_validation_certificate_bytes", "mean_arc_certificate_bytes",
			"mean_decision_certificate_bytes", "mean_handoff_wire_bytes",
			"mean_mvba_pd_data_sent_bytes", "mean_mvba_pd_data_recv_bytes",
			"mean_mvba_rc_data_sent_bytes", "mean_mvba_rc_data_recv_bytes",
			"mean_mvba_certificate_sent_bytes", "mean_mvba_certificate_recv_bytes",
		} {
			if value := benchNumericField(t, line, field); value <= 0 {
				t.Fatalf("four-node V2 benchmark field %s=%f, want > 0", field, value)
			}
		}
		for _, field := range []string{
			"mean_proposer_component_recovery_sent_bytes", "mean_proposer_component_recovery_recv_bytes",
			"mean_proposer_component_recovery_ms", "mean_proposer_catalog_verify_ms",
			"mean_proposer_catalog_scan_count",
			"mean_validator_component_recovery_sent_bytes", "mean_validator_component_recovery_recv_bytes",
			"mean_validator_component_recovery_ms",
			"mean_validator_aggregate_recovery_sent_bytes", "mean_validator_aggregate_recovery_recv_bytes",
			"mean_validator_aggregate_recovery_ms",
			"mean_arc_formation_ms", "mean_vcert_formation_ms", "mean_deccert_formation_ms",
			"mean_scalar_bounded_dlog_ms", "mean_blinding_group_decryption_ms",
			"mean_component_apdb_dispersal_sent_bytes", "mean_component_apdb_dispersal_recv_bytes",
			"mean_pool_coin_sent_bytes", "mean_pool_coin_recv_bytes",
			"mean_validation_request_sent_bytes", "mean_validation_request_recv_bytes",
			"mean_aggregate_apdb_dispersal_sent_bytes", "mean_aggregate_apdb_dispersal_recv_bytes",
			"mean_candidate_relay_sent_bytes", "mean_candidate_relay_recv_bytes",
			"mean_decision_handoff_sent_bytes", "mean_decision_handoff_recv_bytes",
			"mean_new_aggregate_recovery_sent_bytes", "mean_new_aggregate_recovery_recv_bytes",
			"mean_new_aggregate_recovery_ms",
			"mean_new_share_exchange_sent_bytes", "mean_new_share_exchange_recv_bytes",
		} {
			metricTotals[field] += benchNumericField(t, line, field)
		}
		if rejected := benchNumericField(t, line, "mean_proposer_rejected_component_count"); rejected != 0 {
			t.Fatalf("all-honest four-node benchmark rejected component count=%f, want 0", rejected)
		}
	}
	for field, total := range metricTotals {
		if total <= 0 {
			t.Fatalf("four-node V2 benchmark aggregate field %s=%f, want > 0", field, total)
		}
	}
}

func TestBenchMultiProcessN32PrivateStyle(t *testing.T) {
	if os.Getenv("RLADKR_RUN_N32_LOCAL_BENCH") != "1" {
		t.Skip("set RLADKR_RUN_N32_LOCAL_BENCH=1 to run the 32-process private-style benchmark")
	}
	localNodeSets := make([][]int, 32)
	for node := range localNodeSets {
		localNodeSets[node] = []int{node}
	}
	results := runBenchProcessesDetailedWithTopology(t, benchProcessTopology{
		n: 32, f: 10, kappa: 11, timeout: 5 * time.Minute, localNodeSets: localNodeSets,
	})
	var proposerSlotsTotal float64
	var catalogVerifyTotal float64
	verifiedProposers := 0
	for node, result := range results {
		line := extractBenchLine(t, result.stdout)
		if !strings.Contains(line, "success_runs=1") {
			t.Fatalf("n32 node %d did not complete: %s", node, line)
		}
		proposerSlotsTotal += benchNumericField(t, line, "proposer_slots_ms")
		catalogVerify := benchNumericField(t, line, "mean_proposer_catalog_verify_ms")
		catalogVerifyTotal += catalogVerify
		if catalogVerify > 0 {
			verifiedProposers++
			t.Logf("n32 proposer node=%d slots_ms=%.2f catalog_verify_ms=%.2f recovery_ms=%.2f",
				node,
				benchNumericField(t, line, "proposer_slots_ms"),
				catalogVerify,
				benchNumericField(t, line, "mean_proposer_component_recovery_ms"),
			)
		}
	}
	if verifiedProposers == 0 || catalogVerifyTotal <= 0 {
		t.Fatal("n32 run completed without proposer catalog verification metrics")
	}
	t.Logf("n32 mean proposer_slots_ms=%.2f verified_proposers=%d mean_catalog_verify_ms=%.2f",
		proposerSlotsTotal/float64(len(results)), verifiedProposers, catalogVerifyTotal/float64(verifiedProposers))
}

func benchNumericField(t *testing.T, line, name string) float64 {
	t.Helper()
	for _, token := range strings.Fields(line) {
		key, value, ok := strings.Cut(token, "=")
		if !ok || key != name {
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatalf("parse benchmark field %s=%q: %v", name, value, err)
		}
		return parsed
	}
	t.Fatalf("benchmark output missing numeric field %s: %s", name, line)
	return 0
}

func runBenchProcesses(t *testing.T) []string {
	t.Helper()
	return runBenchLines(runBenchProcessesDetailedWithTopology(t, benchProcessTopology{
		n:       2,
		f:       0,
		kappa:   1,
		timeout: 45 * time.Second,
		localNodeSets: [][]int{
			{0},
			{1},
		},
	}))
}

type benchProcessTopology struct {
	n             int
	f             int
	kappa         int
	timeout       time.Duration
	localNodeSets [][]int
}

func runBenchProcessesDetailedWithTopology(t *testing.T, topo benchProcessTopology) []benchProcResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), topo.timeout+2*time.Minute)
	defer cancel()
	workdir := filepath.Dir(filepath.Dir(mustGetwd(t)))
	benchBinary := filepath.Join(t.TempDir(), "rladkrbench")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", benchBinary, "./cmd/rladkrbench")
	build.Dir = workdir
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build multiprocess benchmark binary: %v\n%s", err, output)
	}
	basePort := uniqueBasePort(t)
	addrParts := make([]string, 0, topo.n)
	mvbaAddrParts := make([]string, 0, topo.n)
	for i := 0; i < topo.n; i++ {
		addrParts = append(addrParts, fmt.Sprintf("%d=127.0.0.1:%d", i, basePort+i))
		mvbaAddrParts = append(mvbaAddrParts, fmt.Sprintf("%d=127.0.0.1:%d", i, basePort+500+i))
	}
	addrMap := strings.Join(addrParts, ",")
	mvbaAddrMap := strings.Join(mvbaAddrParts, ",")
	keyRoot := t.TempDir()
	publicKeyDir := filepath.Join(keyRoot, "public")
	secretKeyDir := filepath.Join(keyRoot, "secrets")
	oldMembers := make([]int, topo.n)
	receiverIDs := make([]int, topo.n)
	for i := 0; i < topo.n; i++ {
		oldMembers[i] = i
		receiverIDs[i] = topo.n + i
	}
	sampleSize := 3
	if topo.n < sampleSize {
		sampleSize = 1
	}
	if err := core.GenerateCVV2KeyMaterial(publicKeyDir, secretKeyDir, core.Config{
		SID: "rladkr-go-bench", Epoch: 1,
		OldCommittee: oldMembers, NewCommittee: receiverIDs,
		OldFaults: topo.f, NewFaults: topo.f,
		CVProposerSampleSize: sampleSize, CVValidatorSampleSize: sampleSize,
	}); err != nil {
		t.Fatalf("generate multiprocess V2 keys: %v", err)
	}
	args := []string{
		"-n", fmt.Sprintf("%d", topo.n),
		"-f", fmt.Sprintf("%d", topo.f),
		"-kappa", fmt.Sprintf("%d", topo.kappa),
		"-cv-proposer-sample", fmt.Sprintf("%d", sampleSize),
		"-cv-validator-sample", fmt.Sprintf("%d", sampleSize),
		"-runs", "1",
		"-epochs", "1",
		"-transport", "tcp-distributed",
		"-bind-host", "127.0.0.1",
		"-base-port", fmt.Sprintf("%d", basePort),
		"-timeout", topo.timeout.String(),
	}
	results := make([]benchProcResult, len(topo.localNodeSets))
	chans := make([]chan benchProcResult, len(topo.localNodeSets))
	for idx, localSet := range topo.localNodeSets {
		cmd := exec.CommandContext(ctx, benchBinary, args...)
		cmd.Dir = workdir
		localReceivers := make([]int, len(localSet))
		for i, nodeID := range localSet {
			localReceivers[i] = topo.n + nodeID
		}
		cmd.Env = append(os.Environ(),
			"RLADKR_LOCAL_NODE_IDS="+joinIDs(localSet),
			"RLADKR_LOCAL_RECEIVER_IDS="+joinIDs(localReceivers),
			"RLADKR_NODE_ADDRS="+addrMap,
			"RLADKR_MVBA_NODE_ADDRS="+mvbaAddrMap,
			"RLADKR_DIAL_HOST=127.0.0.1",
			"RLADKR_CV_PUBLIC_KEY_DIR="+publicKeyDir,
			"RLADKR_CV_LOCAL_SECRET_DIR="+secretKeyDir,
			"RLADKR_ARTIFACT_CACHE_DIR="+filepath.Join(keyRoot, fmt.Sprintf("node-%d", idx)),
		)
		chans[idx] = make(chan benchProcResult, 1)
		go func(i int, c *exec.Cmd) { chans[i] <- runBenchCommand(c) }(idx, cmd)
	}
	for idx := range chans {
		results[idx] = <-chans[idx]
	}
	for idx, res := range results {
		if res.err != nil {
			t.Fatalf("bench process %d failed: %v\nstdout:\n%s\nstderr:\n%s", idx, res.err, res.stdout, res.stderr)
		}
	}
	return results
}

type benchProcResult struct {
	stdout string
	stderr string
	err    error
}

func runBenchCommand(cmd *exec.Cmd) benchProcResult {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return benchProcResult{
		stdout: stdout.String(),
		stderr: stderr.String(),
		err:    err,
	}
}

func runBenchLines(results []benchProcResult) []string {
	lines := make([]string, 0, len(results))
	for _, res := range results {
		lines = append(lines, extractBenchLine(nil, res.stdout))
	}
	return lines
}

func extractBenchLine(t *testing.T, stdout string) string {
	if t != nil {
		t.Helper()
	}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "E2E_BENCH_RESULT ") {
			return line
		}
	}
	if t != nil {
		t.Fatalf("missing bench result line in stdout: %s", stdout)
	}
	return ""
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	return wd
}

func uniqueBasePort(t *testing.T) int {
	t.Helper()
	return 43000 + (int(time.Now().UnixNano()/1e6) % 1000)
}

func joinIDs(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ",")
}
