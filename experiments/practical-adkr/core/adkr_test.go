package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Keep fixed listeners below Linux's ephemeral range; APDB reply listeners
// bind to :0 and must not collide with these protocol ports.
var testPortBase uint32 = 12000

func nextTestBase(span int) int {
	return int(atomic.AddUint32(&testPortBase, uint32(span)))
}

func buildAddrCSV(ids []int, base int) string {
	parts := make([]string, 0, len(ids))
	for i, id := range ids {
		parts = append(parts, fmt.Sprintf("%d=127.0.0.1:%d", id, base+i))
	}
	return strings.Join(parts, ",")
}

func buildIDsCSV(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ",")
}

// TestDXTDealAndVerify tests the DXT+ interactive PVSS dealing and verification.
func TestDXTDealAndVerify(t *testing.T) {
	protoIDs := []int{0, 1, 2, 3, 10, 11, 12, 13}
	cfg := Config{
		SID:                  "test-dxt",
		OldCommittee:         []int{0, 1, 2, 3},
		NewCommittee:         []int{10, 11, 12, 13},
		F:                    1,
		PaillierBits:         2048,
		ProtocolNodeAddrs:    buildAddrCSV(protoIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(protoIDs),
	}

	dxt := setupDXTBackend(t, cfg)
	ctx := context.Background()

	// Deal from dealer 0
	tr, shares, err := dxt.Deal(ctx, 0, nil)
	if err != nil {
		t.Fatalf("Deal failed: %v", err)
	}

	// Verify transcript has correct structure
	if tr.Dealer != 0 {
		t.Fatal("wrong dealer ID")
	}
	if len(tr.Commitments) != len(cfg.NewCommittee) {
		t.Fatalf("expected %d commitments, got %d", len(cfg.NewCommittee), len(tr.Commitments))
	}
	if len(tr.Signatures) < 2*cfg.F+1 {
		t.Fatalf("expected >= %d signatures, got %d", 2*cfg.F+1, len(tr.Signatures))
	}
	t.Logf("DXT Deal: %d commitments, %d signatures, %d VE ciphertexts",
		len(tr.Commitments), len(tr.Signatures), len(tr.Ciphertexts))

	// Verify transcript from each new-committee node's perspective
	for _, rid := range cfg.NewCommittee {
		if !dxt.VerifyTranscript(rid, tr) {
			t.Fatalf("VerifyTranscript failed for node %d", rid)
		}
	}

	// Partial verify (distributed verification)
	for _, rid := range cfg.NewCommittee {
		if !dxt.PartialVerify(rid, tr) {
			t.Fatalf("PartialVerify failed for node %d", rid)
		}
	}

	_ = shares
	t.Log("TestDXTDealAndVerify PASSED")
}

// TestPracticalADKR tests the full ADKR protocol flow.
func TestPracticalADKR(t *testing.T) {
	t.Skip("process-local PracticalADKR shortcut removed; use distributed strict TCP benchmark")
	oldIDs := []int{0, 1, 2, 3}
	protoIDs := []int{0, 1, 2, 3, 10, 11, 12, 13}
	cfg := Config{
		SID:                  "test-adkr",
		OldCommittee:         []int{0, 1, 2, 3},
		NewCommittee:         []int{10, 11, 12, 13},
		F:                    1,
		Kappa:                2,
		PaillierBits:         2048,
		MVBANodeAddrs:        buildAddrCSV(oldIDs, nextTestBase(300)),
		MVBALocalNodeIDs:     buildIDsCSV(oldIDs),
		ProtocolNodeAddrs:    buildAddrCSV(protoIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(protoIDs),
	}

	ctx := context.Background()
	result, err := RunPracticalADKR(ctx, cfg)
	if err != nil {
		t.Fatalf("RunPracticalADKR failed: %v", err)
	}

	// Verify results
	if len(result.DecidedSet) == 0 {
		t.Fatal("empty decided set")
	}
	if len(result.SelectedTranscripts) == 0 {
		t.Fatal("no transcripts selected by coin")
	}
	if len(result.SelectedTranscripts) > cfg.Kappa {
		t.Fatalf("selected %d transcripts, expected <= %d", len(result.SelectedTranscripts), cfg.Kappa)
	}
	if len(result.RecoveredTranscripts) == 0 {
		t.Fatal("no transcripts recovered through recast path")
	}
	for _, dealer := range result.SelectedTranscripts {
		tr, ok := result.RecoveredTranscripts[dealer]
		if !ok || tr == nil {
			t.Fatalf("missing recovered transcript for dealer %d", dealer)
		}
	}

	// Every new-committee node should have a share
	for _, rid := range cfg.NewCommittee {
		share, ok := result.NewShares[rid]
		if !ok || len(share) == 0 {
			t.Fatalf("missing share for new-committee node %d", rid)
		}
		if !bytes.Equal(commitScalar(elliptic.P256(), new(big.Int).SetBytes(share)), result.NewPublicShares[rid]) {
			t.Fatalf("private/public share mismatch for new-committee node %d", rid)
		}
	}
	if len(result.NewThresholdPK) == 0 || len(result.NewPublicShares) != len(cfg.NewCommittee) {
		t.Fatal("Algorithm 3 did not output the threshold public key and complete public-share vector")
	}

	t.Logf("Practical ADKR completed:")
	t.Logf("  Decided set: %v", result.DecidedSet)
	t.Logf("  Selected transcripts (κ=%d): %v", cfg.Kappa, result.SelectedTranscripts)
	t.Logf("  Agreement mode: %s", result.AgreementMode)
	t.Logf("  New shares distributed to %d nodes", len(result.NewShares))
	t.Log("TestPracticalADKR PASSED")
}

// TestPracticalADKRLarger tests with n=7, f=2 (larger committee).
func TestPracticalADKRLarger(t *testing.T) {
	t.Skip("process-local PracticalADKR shortcut removed; use distributed strict TCP benchmark")
	n := 7
	f := 2
	old := make([]int, n)
	newC := make([]int, n)
	for i := 0; i < n; i++ {
		old[i] = i
		newC[i] = 100 + i
	}

	cfg := Config{
		SID:                  "test-adkr-large",
		OldCommittee:         old,
		NewCommittee:         newC,
		F:                    f,
		Kappa:                3,
		PaillierBits:         2048,
		MVBANodeAddrs:        buildAddrCSV(old, nextTestBase(400)),
		MVBALocalNodeIDs:     buildIDsCSV(old),
		ProtocolNodeAddrs:    buildAddrCSV(append(append([]int(nil), old...), newC...), nextTestBase(400)),
		ProtocolLocalNodeIDs: buildIDsCSV(append(append([]int(nil), old...), newC...)),
	}

	ctx := context.Background()
	result, err := RunPracticalADKR(ctx, cfg)
	if err != nil {
		t.Fatalf("RunPracticalADKR (n=%d) failed: %v", n, err)
	}

	if len(result.NewShares) != n {
		t.Fatalf("expected %d shares, got %d", n, len(result.NewShares))
	}
	if len(result.RecoveredTranscripts) == 0 {
		t.Fatal("expected recovered transcripts in larger run")
	}

	t.Logf("Practical ADKR (n=%d, f=%d, κ=%d) completed:", n, f, cfg.Kappa)
	t.Logf("  Decided: %v", result.DecidedSet)
	t.Logf("  Selected: %v", result.SelectedTranscripts)
	t.Log("TestPracticalADKRLarger PASSED")
}

func TestPracticalADKRAgreementUsesDumboMVBA(t *testing.T) {
	t.Skip("process-local PracticalADKR shortcut removed; use distributed strict TCP benchmark")
	oldIDs := []int{0, 1, 2, 3}
	protoIDs := []int{0, 1, 2, 3, 10, 11, 12, 13}
	cfg := Config{
		SID:                  "test-adkr-mvba-mode",
		OldCommittee:         []int{0, 1, 2, 3},
		NewCommittee:         []int{10, 11, 12, 13},
		F:                    1,
		Kappa:                2,
		PaillierBits:         2048,
		MVBANodeAddrs:        buildAddrCSV(oldIDs, nextTestBase(300)),
		MVBALocalNodeIDs:     buildIDsCSV(oldIDs),
		ProtocolNodeAddrs:    buildAddrCSV(protoIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(protoIDs),
	}
	ctx := context.Background()
	result, err := RunPracticalADKR(ctx, cfg)
	if err != nil {
		t.Fatalf("RunPracticalADKR failed: %v", err)
	}
	if result.AgreementMode == "simulated-mvba" {
		t.Fatalf("agreement mode should use dumbomvba-go, got %q", result.AgreementMode)
	}
}

// --- Test helpers ---

func setupDXTBackend(t *testing.T, cfg Config) *DXTBackend {
	t.Helper()

	importEC := func(ids []int) (map[int]*ecdsa.PrivateKey, map[int]*ecdsa.PublicKey) {
		priv := make(map[int]*ecdsa.PrivateKey, len(ids))
		pub := make(map[int]*ecdsa.PublicKey, len(ids))
		for _, id := range ids {
			sk, err := generateECDSAKey()
			if err != nil {
				t.Fatal(err)
			}
			priv[id] = sk
			pub[id] = &sk.PublicKey
		}
		return priv, pub
	}

	dealerPriv, dealerPub := importEC(cfg.OldCommittee)
	recipSignPriv, recipSignPub := importEC(cfg.NewCommittee)

	recipPub := make(map[int]*PaillierPublicKey, len(cfg.NewCommittee))
	recipPriv := make(map[int]*PaillierPrivateKey, len(cfg.NewCommittee))
	bits := cfg.PaillierBits
	if bits <= 0 {
		bits = 1024
	}
	for _, id := range cfg.NewCommittee {
		sk, err := GeneratePaillierKey(bits)
		if err != nil {
			t.Fatal(err)
		}
		recipPriv[id] = sk
		recipPub[id] = sk.PublicKey
	}

	dxt, err := NewDXTBackend(cfg.OldCommittee, cfg.NewCommittee, cfg.F,
		dealerPriv, dealerPub, recipPub, recipPriv, recipSignPriv, recipSignPub,
		cfg.ProtocolNodeAddrs, cfg.ProtocolLocalNodeIDs,
	)
	if err != nil {
		t.Fatal(err)
	}
	compKeys, err := generatePracticalCompKeys(cfg.NewCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if err := dxt.setCompPublicKeys(compKeys.public); err != nil {
		t.Fatal(err)
	}
	return dxt
}

func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func TestAPDBCertificateThreshold(t *testing.T) {
	if got := apdbCertificateThreshold(1, 4); got != 3 {
		t.Fatalf("threshold f=1,n=4 = %d, want 3", got)
	}
	if got := apdbCertificateThreshold(2, 7); got != 5 {
		t.Fatalf("threshold f=2,n=7 = %d, want 5", got)
	}
	if got := apdbCertificateThreshold(85, 256); got != 171 {
		t.Fatalf("threshold f=85,n=256 = %d, want 171", got)
	}
	if got := apdbCertificateThreshold(2, 8); got != 6 {
		t.Fatalf("receipt threshold f=2,n=8 = %d, want 6", got)
	}
	if got := apdbFinishedSetThreshold(2, 8); got != 5 {
		t.Fatalf("finished-set threshold f=2,n=8 = %d, want 5", got)
	}
}

func TestVerifyAPDBCertificateRejectsUndersizedQuorum(t *testing.T) {
	nodePub := make(map[int]ed25519.PublicKey, 4)
	nodePriv := make(map[int]ed25519.PrivateKey, 4)
	for i := 0; i < 4; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodePub[i] = pub
		nodePriv[i] = priv
	}
	root := sha256.Sum256([]byte("root"))
	data := []byte("stored APDB payload")
	receipts := make([]APDBReceipt, 0, 2)
	for i := 0; i < 2; i++ {
		chunkHash := hashChunk(root[:], 7, i, data)
		msg := hashReceiptMsg(7, i, root[:], chunkHash)
		receipts = append(receipts, APDBReceipt{
			NodeID:    i,
			Sender:    7,
			ChunkHash: chunkHash,
			Signature: ed25519.Sign(nodePriv[i], msg),
		})
	}
	cert := APDBCertificate{Sender: 7, Root: root[:], Receipts: receipts}
	if verifyAPDBCertificate(cert, nodePub) {
		t.Fatal("expected undersized certificate to be rejected")
	}
}

func TestAPDBReceiptBindsTranscriptRootAndStoredData(t *testing.T) {
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", t.TempDir())
	t.Setenv("PRACTICAL_RUN_ID", "apdb-binding-test")
	cfg := Config{SID: "apdb-binding", NewCommittee: []int{10, 11, 12, 13}}
	old := []int{0, 1, 2, 3}
	tr := DXTTranscript{
		Dealer:      7,
		Commitments: map[int][]byte{10: []byte("commitment")},
		Ciphertexts: map[int][]byte{},
		Proofs:      map[int][]byte{},
		Signatures:  map[int][]byte{},
	}
	raw, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	root := sha256.Sum256(raw)
	req := apdbReceiptRequest{Dealer: tr.Dealer, Root: root[:], TR: tr}
	canonical, err := canonicalAPDBReceiptData(&req)
	if err != nil || !bytes.Equal(canonical, raw) {
		t.Fatalf("valid transcript/root rejected: err=%v", err)
	}

	badRootReq := req
	badRootReq.Root = append([]byte(nil), req.Root...)
	badRootReq.Root[0] ^= 1
	if _, err := canonicalAPDBReceiptData(&badRootReq); err == nil {
		t.Fatal("accepted APDB request whose root does not bind TR")
	}
	badDealerReq := req
	badDealerReq.Dealer++
	if _, err := canonicalAPDBReceiptData(&badDealerReq); err == nil {
		t.Fatal("accepted APDB request whose dealer does not match TR")
	}

	if err := persistAPDBTranscript(cfg, old, 1, tr.Dealer, root[:], raw); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(apdbTranscriptStorePath(cfg, old, 1, tr.Dealer, root[:]))
	if err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("write-before-sign store mismatch: err=%v", err)
	}
	mutated := append([]byte(nil), raw...)
	mutated = append(mutated, 'x')
	if err := persistAPDBTranscript(cfg, old, 1, tr.Dealer, root[:], mutated); err == nil {
		t.Fatal("stored APDB bytes under an unrelated root")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chunkHash := hashChunk(root[:], tr.Dealer, 1, raw)
	receipt := APDBReceipt{
		NodeID:    1,
		Sender:    tr.Dealer,
		ChunkHash: chunkHash,
		Signature: ed25519.Sign(priv, hashReceiptMsg(tr.Dealer, 1, root[:], chunkHash)),
	}
	if !verifyAPDBReceiptForData(receipt, tr.Dealer, root[:], raw, map[int]ed25519.PublicKey{1: pub}) {
		t.Fatal("valid data-bound APDB receipt rejected")
	}
	if verifyAPDBReceiptForData(receipt, tr.Dealer, root[:], mutated, map[int]ed25519.PublicKey{1: pub}) {
		t.Fatal("APDB receipt accepted mutated stored data")
	}
}

func TestMVBAExternalValidityRequiresCanonicalAPDBLocks(t *testing.T) {
	old := []int{0, 1, 2, 3}
	nodePub := make(map[int]ed25519.PublicKey, len(old))
	nodePriv := make(map[int]ed25519.PrivateKey, len(old))
	for _, nodeID := range old {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodePub[nodeID] = pub
		nodePriv[nodeID] = priv
	}

	payload := mvbaSetPayload{Proposer: 0, Set: []int{0, 1, 2}}
	for _, dealer := range payload.Set {
		data := []byte(fmt.Sprintf("transcript-%d", dealer))
		root := sha256.Sum256(data)
		cert := APDBCertificate{Sender: dealer, Root: append([]byte(nil), root[:]...)}
		for _, nodeID := range old[:3] {
			chunkHash := hashChunk(root[:], dealer, nodeID, data)
			cert.Receipts = append(cert.Receipts, APDBReceipt{
				NodeID:    nodeID,
				Sender:    dealer,
				ChunkHash: chunkHash,
				Signature: ed25519.Sign(nodePriv[nodeID], hashReceiptMsg(dealer, nodeID, root[:], chunkHash)),
			})
		}
		payload.Certificates = append(payload.Certificates, cert)
	}
	raw, err := json.Marshal(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateMVBASetPayload(raw, 0, old, 3, nodePub); err != nil {
		t.Fatalf("valid APDB-locked MVBA payload rejected: %v", err)
	}
	if _, err := validateMVBASetPayload(raw, 1, old, 3, nodePub); err == nil {
		t.Fatal("accepted MVBA payload under a different proposer")
	}

	missing := payload
	missing.Certificates = append([]APDBCertificate(nil), payload.Certificates[:2]...)
	missingRaw, _ := json.Marshal(&missing)
	if _, err := validateMVBASetPayload(missingRaw, 0, old, 3, nodePub); err == nil {
		t.Fatal("accepted MVBA payload without one dealer lock")
	}

	duplicate := payload
	duplicate.Set = []int{0, 1, 1}
	duplicateRaw, _ := json.Marshal(&duplicate)
	if _, err := validateMVBASetPayload(duplicateRaw, 0, old, 3, nodePub); err == nil {
		t.Fatal("accepted non-canonical duplicate dealer set")
	}

	tampered := payload
	tampered.Certificates = append([]APDBCertificate(nil), payload.Certificates...)
	tampered.Certificates[0].Receipts = append([]APDBReceipt(nil), payload.Certificates[0].Receipts...)
	tampered.Certificates[0].Receipts[0].Signature = append([]byte(nil), payload.Certificates[0].Receipts[0].Signature...)
	tampered.Certificates[0].Receipts[0].Signature[0] ^= 1
	tamperedRaw, _ := json.Marshal(&tampered)
	if _, err := validateMVBASetPayload(tamperedRaw, 0, old, 3, nodePub); err == nil {
		t.Fatal("accepted MVBA payload with forged APDB receipt")
	}
}

func TestMVBAExternalValiditySeparatesDealerAndReceiptThresholds(t *testing.T) {
	old := []int{0, 1, 2, 3, 4}
	nodePub := make(map[int]ed25519.PublicKey, len(old))
	nodePriv := make(map[int]ed25519.PrivateKey, len(old))
	for _, nodeID := range old {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodePub[nodeID] = pub
		nodePriv[nodeID] = priv
	}

	payload := mvbaSetPayload{Proposer: 0, Set: []int{0, 1, 2}}
	for _, dealer := range payload.Set {
		data := []byte(fmt.Sprintf("transcript-%d", dealer))
		root := sha256.Sum256(data)
		cert := APDBCertificate{Sender: dealer, Root: append([]byte(nil), root[:]...)}
		for _, nodeID := range old[:4] {
			chunkHash := hashChunk(root[:], dealer, nodeID, data)
			cert.Receipts = append(cert.Receipts, APDBReceipt{
				NodeID: nodeID, Sender: dealer, ChunkHash: chunkHash,
				Signature: ed25519.Sign(nodePriv[nodeID], hashReceiptMsg(dealer, nodeID, root[:], chunkHash)),
			})
		}
		payload.Certificates = append(payload.Certificates, cert)
	}
	raw, err := json.Marshal(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateMVBASetPayload(raw, 0, old, 3, nodePub); err != nil {
		t.Fatalf("valid 2f+1 dealer set with n-f receipt certificates rejected: %v", err)
	}
}

func TestPracticalRunIDUsesEnvOverride(t *testing.T) {
	t.Setenv("PRACTICAL_RUN_ID", "manual-run")
	cfg := Config{SID: "sid"}
	got := practicalRunID(cfg, []int{1, 2}, []int{3, 4})
	if got != "manual-run" {
		t.Fatalf("run id = %q, want manual-run", got)
	}
}

func TestPracticalRunIDStableWithoutEnv(t *testing.T) {
	cfg := Config{SID: "sid"}
	a := practicalRunID(cfg, []int{1, 2}, []int{3, 4})
	b := practicalRunID(cfg, []int{1, 2}, []int{3, 4})
	c := practicalRunID(cfg, []int{1, 2}, []int{3, 5})
	if a != b {
		t.Fatalf("expected stable run id, got %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("expected committee change to alter run id, got same %q", a)
	}
}

func TestCacheLockStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.lock")
	if err := os.WriteFile(path, []byte("lock"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-20 * time.Minute)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
	stale, err := cacheLockStale(path, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Fatal("expected stale lock to be detected")
	}
}

func TestBoundedQueueSize(t *testing.T) {
	if got := boundedQueueSize(1, 32, 128); got != 32 {
		t.Fatalf("queue size floor mismatch: %d", got)
	}
	if got := boundedQueueSize(256, 32, 128); got != 128 {
		t.Fatalf("queue size ceiling mismatch: %d", got)
	}
	if got := boundedQueueSize(64, 32, 128); got != 64 {
		t.Fatalf("queue size passthrough mismatch: %d", got)
	}
}

func TestRecoverInitialFetchFanout(t *testing.T) {
	if got := recoverInitialFetchFanout(22, 21, 64); got != 22 {
		t.Fatalf("fanout n64 mismatch: got %d want 22", got)
	}
	if got := recoverInitialFetchFanout(34, 31, 96); got != 34 {
		t.Fatalf("fanout n96 mismatch: got %d want 34", got)
	}
	if got := recoverInitialFetchFanout(43, 42, 127); got != 43 {
		t.Fatalf("fanout n127 mismatch: got %d want 43", got)
	}
}

func TestRecoverRetryStep(t *testing.T) {
	if got := recoverRetryStep(21); got != 5 {
		t.Fatalf("retry step f21 mismatch: got %d want 5", got)
	}
	if got := recoverRetryStep(31); got != 7 {
		t.Fatalf("retry step f31 mismatch: got %d want 7", got)
	}
	if got := recoverRetryStep(42); got != 10 {
		t.Fatalf("retry step f42 mismatch: got %d want 10", got)
	}
}

func TestRecoverSpeculativeExtra(t *testing.T) {
	if got := recoverSpeculativeExtra(21); got != 10 {
		t.Fatalf("speculative extra f21 mismatch: got %d want 10", got)
	}
	if got := recoverSpeculativeExtra(31); got != 15 {
		t.Fatalf("speculative extra f31 mismatch: got %d want 15", got)
	}
}

func TestRecoverStoreHolderPosition(t *testing.T) {
	old := []int{0, 1, 2, 3, 4, 5, 6}
	recipient := 9 // start index = 2
	activeCount := 4
	cases := map[int]int{
		0: -1,
		1: -1,
		2: 0,
		3: 1,
		4: 2,
		5: 3,
		6: -1,
	}
	for holder, want := range cases {
		if got := recoverStoreHolderPosition(old, recipient, holder, activeCount); got != want {
			t.Fatalf("holder %d position = %d, want %d", holder, got, want)
		}
	}
	if got := recoverStoreHolderPosition(old, recipient, 99, activeCount); got != -1 {
		t.Fatalf("missing holder position = %d, want -1", got)
	}
}

func TestAPDBProposalUsesFinishedPDQuorumOnly(t *testing.T) {
	required := 2*2 + 1
	valid := []int{6, 5, 4, 3, 2, 1, 0}
	got := stableFirst(valid, required)
	want := []int{0, 1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("proposal size = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("proposal[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}
