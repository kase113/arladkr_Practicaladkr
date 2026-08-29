package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestDXTTranscriptWireCompressionRoundTrip(t *testing.T) {
	transcript := &DXTTranscript{Dealer: 3, Commitments: map[int][]byte{}, Ciphertexts: map[int][]byte{}, BlindingCiphertexts: map[int]DXTBlindingCiphertext{}}
	for i := 0; i < 32; i++ {
		transcript.Commitments[i] = bytes.Repeat([]byte{byte(i)}, 33)
		transcript.Ciphertexts[i] = bytes.Repeat([]byte{byte(i + 1)}, 384)
		transcript.BlindingCiphertexts[i] = DXTBlindingCiphertext{C0: bytes.Repeat([]byte{2}, 33), C1: bytes.Repeat([]byte{3}, 33)}
	}
	digest, err := dxtTranscriptDigest(transcript)
	if err != nil {
		t.Fatal(err)
	}
	wire := dxtTranscriptWire{Kind: dxtTranscriptWireKind, SID: "sid", Epoch: 1, Dealer: 3, Transcript: transcript, TranscriptDigest: digest}
	compressed, err := marshalDXTTranscriptWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(plain) {
		t.Fatalf("compressed wire did not shrink: compressed=%d plain=%d", len(compressed), len(plain))
	}
	var got dxtTranscriptWire
	if err := unmarshalDXTTranscriptWire(compressed, &got); err != nil {
		t.Fatal(err)
	}
	gotDigest, err := dxtTranscriptDigest(got.Transcript)
	if err != nil || !bytes.Equal(gotDigest, digest) {
		t.Fatalf("compressed transcript digest changed: err=%v", err)
	}
}

func TestNetworkDXTReceiverReadinessWaitsForQuorum(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "network-dxt-readiness", Epoch: 4, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		ProtocolNodeAddrs: addresses, DXTNodeAddrs: addresses, ProtocolLocalNodeIDs: "0,10",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := startDXTNetworkService(ctx, cfg, old, &DXTBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()

	ready := make(chan error, 1)
	go func() { ready <- first.waitForReceiverQuorum(ctx, newCommittee, 3) }()
	select {
	case err := <-ready:
		t.Fatalf("readiness returned before quorum: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	services := make([]*dxtNetworkService, 0, 2)
	for index := 1; index <= 2; index++ {
		processCfg := cfg
		processCfg.ProtocolLocalNodeIDs = fmt.Sprintf("%d,%d", old[index], newCommittee[index])
		service, startErr := startDXTNetworkService(ctx, processCfg, old, &DXTBackend{})
		if startErr != nil {
			t.Fatalf("start delayed DXT node %d: %v", index, startErr)
		}
		services = append(services, service)
		defer service.close()
	}
	if err := <-ready; err != nil {
		t.Fatalf("wait for receiver quorum: %v", err)
	}
	resetCommStats(true)
	if !probeDXTReady(ctx, cfg, newCommittee[0], parseNodeAddrMap(addresses)[newCommittee[0]]) {
		t.Fatal("readiness probe rejected the matching run context")
	}
	if sent, received := commStats(); sent != 0 || received != 0 {
		t.Fatalf("readiness traffic entered protocol byte metrics: sent=%d received=%d", sent, received)
	}
	wrongContext := cfg
	wrongContext.Epoch++
	if probeDXTReady(ctx, wrongContext, newCommittee[0], parseNodeAddrMap(addresses)[newCommittee[0]]) {
		t.Fatal("readiness probe accepted the wrong epoch")
	}
}

func TestDXTNetworkTimeoutScalesWithCommittee(t *testing.T) {
	t.Setenv("PRACTICAL_DXT_TIMEOUT_MS", "")
	tests := []struct {
		n    int
		want time.Duration
	}{
		{n: 10, want: 8 * time.Second},
		{n: 32, want: 30 * time.Second},
		{n: 64, want: 90 * time.Second},
		{n: 100, want: 3 * time.Minute},
		{n: 128, want: 5 * time.Minute},
		{n: 256, want: 10 * time.Minute},
	}
	for _, test := range tests {
		if got := dxtNetworkTimeout(test.n); got != test.want {
			t.Fatalf("n=%d timeout=%s want=%s", test.n, got, test.want)
		}
	}
	t.Setenv("PRACTICAL_DXT_TIMEOUT_MS", "1250")
	if got := dxtNetworkTimeout(256); got != 1250*time.Millisecond {
		t.Fatalf("override timeout=%s", got)
	}
}

func TestDXTTranscriptVerificationBudgetsAreBounded(t *testing.T) {
	t.Setenv("PRACTICAL_DXT_VERIFY_WORKERS", "12")
	if got := dxtTranscriptVerifyWorkers(100); got != 4 {
		t.Fatalf("verify workers=%d want=4", got)
	}
	if got := dxtTranscriptVerifyQueueCapacity(10); got != 64 {
		t.Fatalf("small queue=%d want=64", got)
	}
	if got := dxtTranscriptVerifyQueueCapacity(100); got != 200 {
		t.Fatalf("n100 queue=%d want=200", got)
	}
	if got := dxtTranscriptVerifyQueueCapacity(1000); got != 512 {
		t.Fatalf("large queue=%d want=512", got)
	}
}

func TestNetworkDXTCompletesWithoutAllReceiversOrDealers(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "network-dxt-missing-participants", Epoch: 12,
		OldCommittee: old, NewCommittee: newCommittee, F: 1, PaillierBits: 2048,
		ProtocolNodeAddrs: addresses, DXTNodeAddrs: addresses,
	}
	dxt := setupDXTBackend(t, Config{
		SID: cfg.SID, Epoch: cfg.Epoch, OldCommittee: old, NewCommittee: newCommittee,
		F: cfg.F, PaillierBits: cfg.PaillierBits, ProtocolNodeAddrs: addresses,
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	})
	dxt.strictNetwork = true
	dxt.externalReceivers = true
	if err := dxt.setShareStoreDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	services := make(map[int]*dxtNetworkService, 3)
	for index := 0; index < 3; index++ {
		processCfg := cfg
		processCfg.ProtocolLocalNodeIDs = fmt.Sprintf("%d,%d", old[index], newCommittee[index])
		service, err := startDXTNetworkService(ctx, processCfg, old, dxt)
		if err != nil {
			t.Fatalf("start DXT node %d: %v", index, err)
		}
		services[index] = service
		defer service.close()
	}

	// Receiver 13 is absent; each dealer must create a VE lane for it.
	for _, dealer := range old[:3] {
		transcript, _, err := dxt.Deal(ctx, dealer, nil)
		if err != nil {
			t.Fatalf("dealer %d: %v", dealer, err)
		}
		if len(transcript.Signatures) != 3 || len(transcript.Ciphertexts) != 1 || transcript.Ciphertexts[13] == nil {
			t.Fatalf("dealer %d partition: ACK=%d VE=%d", dealer, len(transcript.Signatures), len(transcript.Ciphertexts))
		}
		if !dxt.VerifyTranscript(0, transcript) {
			t.Fatalf("dealer %d transcript failed full verification", dealer)
		}
		if err := services[dealer].publishTranscript(ctx, dealer, transcript); err != nil {
			t.Fatalf("publish dealer %d: %v", dealer, err)
		}
	}

	// Dealer 3 is absent. The remaining services still cross the 2f+1 finished
	// dealer threshold without a filesystem readiness/transcript barrier.
	for node, service := range services {
		transcripts, err := service.waitForTranscripts(ctx, 3)
		if err != nil || len(transcripts) != 3 {
			t.Fatalf("node %d transcripts=%d err=%v", node, len(transcripts), err)
		}
		shares := service.shareSnapshot()
		localReceiver := newCommittee[node]
		for dealer := range transcripts {
			if shares[dealer][localReceiver].S == nil {
				t.Fatalf("node %d lacks its receiver-local share for dealer %d", node, dealer)
			}
			for _, other := range newCommittee[:3] {
				if other != localReceiver && shares[dealer][other].S != nil {
					t.Fatalf("node %d retained receiver %d share", node, other)
				}
			}
		}
	}
}

func TestNetworkDXTRejectsTranscriptBindingMutation(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "network-dxt-binding", Epoch: 21, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		PaillierBits: 2048, ProtocolNodeAddrs: addresses, DXTNodeAddrs: addresses,
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	transcript, _, err := dxt.Deal(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dxtTranscriptDigest(transcript)
	if err != nil {
		t.Fatal(err)
	}
	wire := dxtTranscriptWire{
		Kind: dxtTranscriptWireKind, SID: cfg.SID + "-wrong", Epoch: cfg.Epoch,
		Dealer: 0, Transcript: transcript, TranscriptDigest: digest,
	}
	processCfg := cfg
	processCfg.ProtocolLocalNodeIDs = "0"
	service, err := startDXTNetworkService(context.Background(), processCfg, old, dxt)
	if err != nil {
		t.Fatal(err)
	}
	defer service.close()
	if sendDXTTranscript(context.Background(), cfg, 0, 0, parseNodeAddrMap(addresses)[0], wire) {
		t.Fatal("accepted transcript with mismatched SID")
	}
	if len(service.transcriptSnapshot()) != 0 {
		t.Fatal("binding-mutated transcript entered the local ready set")
	}
}
