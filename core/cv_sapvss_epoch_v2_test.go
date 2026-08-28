package core

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestCVRecoverServiceGraceV2Bounds(t *testing.T) {
	tests := []struct {
		route time.Duration
		want  time.Duration
	}{
		{route: 0, want: 500 * time.Millisecond},
		{route: 300 * time.Millisecond, want: 600 * time.Millisecond},
		{route: time.Second, want: 10 * time.Second},
		{route: 2 * time.Second, want: 10 * time.Second},
		{route: 6 * time.Second, want: 10 * time.Second},
	}
	for _, test := range tests {
		if got := cvRecoverServiceGraceV2(test.route); got != test.want {
			t.Fatalf("route=%v grace=%v want %v", test.route, got, test.want)
		}
	}
}

func TestRunCVEpochV2FourNodeEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real four-node CV V2 epoch in short mode")
	}
	t.Setenv("RLADKR_NODE_ADDRS", "")
	t.Setenv("RLADKR_MVBA_NODE_ADDRS", "")
	t.Setenv("RLADKR_LOCAL_NODE_IDS", "")
	t.Setenv("RLADKR_MVBA_PEER_WAIT_TARGET", "all")
	t.Setenv("RLADKR_MVBA_PEER_WAIT_MS", "30000")

	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "secret")
	base := Config{
		SID: "cv-v2-four-node-epoch", Epoch: 1,
		OldCommittee: []int{0, 1, 2, 3}, NewCommittee: []int{4, 5, 6, 7},
		FOld: 1, FNew: 1, OldFaults: 1, NewFaults: 1,
		CVProposerSampleSize: 3, CVValidatorSampleSize: 3,
		APVSSMode: APVSSModeACKFallback, APVSSFallbackProfile: apvssFallbackFeldmanBatchProfile,
		AgreementTransport: "tcp-distributed", AgreementBindHost: "127.0.0.1",
		AgreementBasePort: cvAvailableEpochV2BasePort(t),
		CVPublicKeyDir:    publicDir, CVLocalSecretDir: secretDir,
		WaitSPBCTimeout: 30 * time.Second, RouteSendTimeout: time.Second,
	}
	if err := GenerateCVV2KeyMaterial(publicDir, secretDir, base); err != nil {
		t.Fatal(err)
	}

	allNodes := append(append([]int(nil), base.OldCommittee...), base.NewCommittee...)
	transport := newCVRouterTestTransport(allNodes, 65536)
	t.Cleanup(func() { _ = transport.Close() })

	type epochResult struct {
		oldID  int
		result *EpochResult
		err    error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	results := make(chan epochResult, len(base.OldCommittee))
	for i, oldID := range base.OldCommittee {
		cfg := base
		cfg.LocalNodeIDs = []int{oldID}
		cfg.CVLocalReceiverIDs = []int{base.NewCommittee[i]}
		cfg.ArtifactCacheDir = filepath.Join(root, fmt.Sprintf("node-%d", oldID))
		cfg.protocolTransport = transport
		go func() {
			result, err := RunEpoch(ctx, cfg)
			results <- epochResult{oldID: oldID, result: result, err: err}
		}()
	}

	got := make([]*EpochResult, len(base.OldCommittee))
	var failures []epochResult
	for range base.OldCommittee {
		out := <-results
		if out.err != nil {
			failures = append(failures, out)
			continue
		}
		got[out.oldID] = out.result
	}
	if len(failures) != 0 {
		for _, failure := range failures {
			t.Logf("CV V2 epoch node %d: %v", failure.oldID, failure.err)
		}
		t.Fatalf("CV V2 epoch failed on %d nodes (coin shares sent=%d)", len(failures), transport.sentCount(cvTagCoinShareV2))
	}
	if senders := transport.sentFromByTag(cvTagPoolOfferV2); len(senders) == 0 || len(senders) > base.CVProposerSampleSize {
		t.Fatalf("sampled proposer Pool senders=%v want between 1 and %d", senders, base.CVProposerSampleSize)
	}
	if senders := transport.sentFromByTag(cvTagValidationRequestV2); len(senders) == 0 || len(senders) > base.CVProposerSampleSize {
		t.Fatalf("sampled proposer validation senders=%v want between 1 and %d", senders, base.CVProposerSampleSize)
	}
	for node, result := range got {
		if result == nil || !result.RecoverAggSuccess || len(result.NewShares) != 1 || len(result.CVReceipts) != 1 {
			t.Fatalf("CV V2 epoch node %d returned incomplete result", node)
		}
		if result.CVAPVSSMode != cvSAPVSSV2ProtocolVersion || result.AgreementMode != "single-mvba-v2" {
			t.Fatalf("production entry node %d returned mode=%q agreement=%q", node, result.CVAPVSSMode, result.AgreementMode)
		}
		if !bytes.Equal(result.AggRLODigest, got[0].AggRLODigest) ||
			!bytes.Equal(result.RecoveredAggregate, got[0].RecoveredAggregate) ||
			!bytes.Equal(result.NewPublicKey, got[0].NewPublicKey) {
			t.Fatalf("CV V2 epoch node %d disagreed on public output", node)
		}
	}
}

func cvAvailableEpochV2BasePort(t *testing.T) int {
	t.Helper()
	for base := 20000; base < 60000; base += 16 {
		listeners := make([]net.Listener, 0, 12)
		available := true
		for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 7, 500, 501, 502, 503} {
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+offset))
			if err != nil {
				available = false
				break
			}
			listeners = append(listeners, listener)
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if available {
			return base
		}
	}
	t.Fatal("no free TCP port range for CV V2 epoch test")
	return 0
}
