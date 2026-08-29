package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecastTCPReadinessCompletesWithoutAllPairs(t *testing.T) {
	artifactDir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", artifactDir)
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "recast-ready-missing-pair", Epoch: 31, OldCommittee: old,
		NewCommittee: newCommittee, F: 1, ProtocolNodeAddrs: addresses,
	}
	addrMap := parseNodeAddrMap(addresses)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	localSet := map[int]struct{}{0: {}, 10: {}}
	localListeners := make(map[int]net.Listener, 2)
	for _, id := range []int{0, 10} {
		listener, err := net.Listen("tcp", addrMap[id])
		if err != nil {
			t.Fatal(err)
		}
		localListeners[id] = listener
		defer listener.Close()
	}

	// Pairs (1,11) and (2,12) answer authenticated readiness probes. Pair
	// (3,13) is completely absent; n-f=3 complete pairs are still sufficient.
	for _, id := range []int{1, 11, 2, 12} {
		listener := startRecastReadyTestResponder(t, ctx, cfg, id, addrMap[id])
		defer listener.Close()
	}
	if err := waitForRecastReadyQuorum(ctx, cfg, old, newCommittee, localSet, localListeners, addrMap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(artifactDir, "recast-ready")); !os.IsNotExist(err) {
		t.Fatalf("recast readiness created a filesystem barrier: err=%v", err)
	}
}

func TestRecastTCPReadinessRejectsContextMutation(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{SID: "recast-ready-binding", Epoch: 44, OldCommittee: old, NewCommittee: newCommittee, F: 1, ProtocolNodeAddrs: addresses}
	addr := parseNodeAddrMap(addresses)[1]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener := startRecastReadyTestResponder(t, ctx, cfg, 1, addr)
	defer listener.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	bad := recastWire{Kind: "ready", SID: cfg.SID + "-wrong", Epoch: cfg.Epoch, Holder: 1}
	body, err := marshalRecastNetworkWire(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	var ack recastWire
	if _, err := readRecastNetworkWire(conn, &ack); err == nil {
		t.Fatal("recast readiness accepted a mismatched SID")
	}
}

func TestRecastCompletionBindsContextReceiverAndRoots(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	cfg := Config{
		SID: "recast-completion-binding", Epoch: 52, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		PaillierBits: 2048, ProtocolNodeAddrs: buildAddrCSV(allIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	root0 := sha256.Sum256([]byte("dealer-0"))
	root2 := sha256.Sum256([]byte("dealer-2"))
	roots := map[int][]byte{0: root0[:], 2: root2[:]}
	digest, err := recastCompletionDigest(cfg, 10, []int{2, 0}, roots)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, dxt.recipientSignPriv[10], digest)
	if err != nil {
		t.Fatal(err)
	}
	wire := recastWire{
		Kind: "completion", SID: cfg.SID, Epoch: cfg.Epoch, Holder: 0, Recipient: 10,
		CompletionDigest: digest, Signature: signature,
	}
	if !verifyRecastCompletion(cfg, wire, []int{0, 2}, roots, dxt) {
		t.Fatal("valid receiver completion was rejected")
	}
	tampered := wire
	tampered.Epoch++
	if verifyRecastCompletion(cfg, tampered, []int{0, 2}, roots, dxt) {
		t.Fatal("completion with mutated epoch was accepted")
	}
	tampered = wire
	tampered.Recipient = 11
	if verifyRecastCompletion(cfg, tampered, []int{0, 2}, roots, dxt) {
		t.Fatal("completion replayed as another receiver was accepted")
	}
	tamperedRoots := map[int][]byte{0: root0[:], 2: append([]byte(nil), root2[:]...)}
	tamperedRoots[2][0] ^= 1
	if verifyRecastCompletion(cfg, wire, []int{0, 2}, tamperedRoots, dxt) {
		t.Fatal("completion with mutated recovered root was accepted")
	}
	if _, err := recastCompletionDigest(cfg, 10, []int{0, 0}, roots); err == nil {
		t.Fatal("completion digest accepted duplicate dealers")
	}
}

func TestRecoverCompletionBarrierIsOptIn(t *testing.T) {
	t.Setenv("PRACTICAL_RECOVER_COMPLETION_WAIT_MS", "")
	if recoverCompletionBarrierEnabled() {
		t.Fatal("completion barrier enabled by default")
	}
	t.Setenv("PRACTICAL_RECOVER_COMPLETION_WAIT_MS", "0")
	if recoverCompletionBarrierEnabled() {
		t.Fatal("zero completion wait enabled the barrier")
	}
	t.Setenv("PRACTICAL_RECOVER_COMPLETION_WAIT_MS", "250")
	if !recoverCompletionBarrierEnabled() {
		t.Fatal("positive completion wait did not enable the completion barrier")
	}
}

func TestListenRecastWithRetrySurvivesTransientPortUse(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := occupied.Addr().String()
	t.Setenv("PRACTICAL_RECOVER_LISTEN_RETRY_MS", "1000")
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = occupied.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := listenRecastWithRetry(ctx, address)
	if err != nil {
		t.Fatalf("listen after transient port use: %v", err)
	}
	_ = listener.Close()
}

func TestRecastNodeAddrMapUsesOptionalPortNamespace(t *testing.T) {
	t.Setenv("PRACTICAL_RECAST_PORT_OFFSET", "3000")
	got, err := recastNodeAddrMap("7=127.0.0.1:41007,8=127.0.0.1:41008")
	if err != nil {
		t.Fatal(err)
	}
	if got[7] != "127.0.0.1:44007" || got[8] != "127.0.0.1:44008" {
		t.Fatalf("recast addresses=%v", got)
	}
	t.Setenv("PRACTICAL_RECAST_PORT_OFFSET", "0")
	got, err = recastNodeAddrMap("7=127.0.0.1:41007")
	if err != nil || got[7] != "127.0.0.1:41007" {
		t.Fatalf("zero offset addresses=%v err=%v", got, err)
	}
}

func TestRecastFramedWireRoundTripRejectsUnframed(t *testing.T) {
	data := make([]byte, 64<<10)
	for offset := 0; offset < len(data); offset += sha256.Size {
		digest := sha256.Sum256([]byte{byte(offset), byte(offset >> 8), byte(offset >> 16)})
		copy(data[offset:], digest[:])
	}
	want := recastWire{
		Kind: "fetch_resp_batch", SID: "recast-frame", Epoch: 91, Holder: 2, Recipient: 10,
		Dealers: []int{3},
		Shards: map[int]RecoverShard{3: {
			Dealer: 3, Index: 2, Root: bytes.Repeat([]byte{7}, sha256.Size),
			DataShards: 3, TotalShards: 7, Data: data,
		}},
	}
	unframed, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := marshalRecastNetworkWire(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) >= len(unframed) || len(frame) < 7 || frame[0] != recastFrameMagic[0] || frame[1] != recastFrameMagic[1] || frame[2] != 1 {
		t.Fatalf("recast frame did not compress JSON bytes: frame=%d unframed=%d mode=%d", len(frame), len(unframed), frame[2])
	}
	var got recastWire
	read, err := readRecastNetworkWire(bytes.NewReader(frame), &got)
	if err != nil {
		t.Fatal(err)
	}
	if read != len(frame) || got.Kind != want.Kind || got.SID != want.SID || got.Epoch != want.Epoch ||
		!bytes.Equal(got.Shards[3].Data, data) {
		t.Fatalf("framed recast round trip mismatch: read=%d frame=%d", read, len(frame))
	}

	unframed = append(unframed, '\n')
	got = recastWire{}
	if _, err = readRecastNetworkWire(bytes.NewReader(unframed), &got); err == nil {
		t.Fatal("unframed recast wire was accepted")
	}
	if _, err := readRecastNetworkWire(bytes.NewReader(frame[:len(frame)-1]), &recastWire{}); err == nil {
		t.Fatal("truncated recast frame was accepted")
	}
}

func startRecastReadyTestResponder(t *testing.T, ctx context.Context, cfg Config, localID int, addr string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var wire recastWire
				if _, err := readRecastNetworkWire(conn, &wire); err == nil {
					respondRecastReady(conn, cfg, localID, wire)
				}
			}()
			select {
			case <-ctx.Done():
				_ = listener.Close()
				return
			default:
			}
		}
	}()
	return listener
}
