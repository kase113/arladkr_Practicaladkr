package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDXTShareChannelEncryptsAndAuthenticates(t *testing.T) {
	dealer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, sr := big.NewInt(123456), big.NewInt(789012)
	wire, err := encryptDXTShare(dealer, &recipient.PublicKey, 4, 9, s, sr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, s.Bytes()) || bytes.Contains(wire, sr.Bytes()) {
		t.Fatal("share ciphertext contains plaintext scalar bytes")
	}
	gotS, gotSR, err := decryptDXTShare(&dealer.PublicKey, recipient, 4, 9, wire)
	if err != nil || gotS.Cmp(s) != 0 || gotSR.Cmp(sr) != 0 {
		t.Fatalf("decrypt mismatch: s=%v sr=%v err=%v", gotS, gotSR, err)
	}
	wire[len(wire)-1] ^= 1
	if _, _, err := decryptDXTShare(&dealer.PublicKey, recipient, 4, 9, wire); err == nil {
		t.Fatal("tampered share ciphertext was accepted")
	}
}

func TestStrictPaillierCacheKeepsPrivateKeysReceiverLocal(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{SID: "strict-cache-test", PaillierBits: 2048, NewCommittee: []int{10, 11, 12}, ProtocolLocalNodeIDs: "11"}
	pub, priv, err := loadOrComputeStrictRecipientPaillierKeys(cfg, cfg.NewCommittee, dir, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 3 || len(priv) != 1 || priv[11] == nil {
		t.Fatalf("unexpected key ownership: public=%d private=%d", len(pub), len(priv))
	}
	base := filepath.Join(dir, paillierCacheFileName(cfg, cfg.NewCommittee))
	publicPath := base + ".public.json"
	raw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("lambda")) || bytes.Contains(raw, []byte("mu")) {
		t.Fatal("public paillier cache contains private key fields")
	}
	info, err := os.Stat(paillierPrivateCachePath(publicPath, 11))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key cache mode=%o, want 600", info.Mode().Perm())
	}
}

func TestDXTLocalShareStoreIsReceiverScoped(t *testing.T) {
	dir := t.TempDir()
	b := &DXTBackend{}
	if err := b.setShareStoreDir(dir); err != nil {
		t.Fatal(err)
	}
	share := SharePair{S: big.NewInt(41), SR: big.NewInt(99)}
	if err := b.storeLocalShare(7, 11, share); err != nil {
		t.Fatal(err)
	}
	got, err := readDXTLocalShare(dir, 7, 11)
	if err != nil || got.S.Cmp(share.S) != 0 || got.SR.Cmp(share.SR) != 0 {
		t.Fatalf("local share mismatch: got=%v err=%v", got, err)
	}
	if _, err := readDXTLocalShare(dir, 7, 12); err == nil {
		t.Fatal("receiver 12 unexpectedly read receiver 11 share")
	}
}

func TestPartialVerifyResultSignatureBindsDigestAndValidity(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := partialVerifyResultWire{
		Dealer:           3,
		Verifier:         1,
		TranscriptDigest: []byte("digest"),
		Valid:            true,
	}
	wire.Signature, err = ecdsa.SignASN1(rand.Reader, priv, partialVerifyResultMessage(&wire))
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, partialVerifyResultMessage(&wire), wire.Signature) {
		t.Fatal("valid partial verification result signature rejected")
	}
	wire.Valid = false
	if ecdsa.VerifyASN1(&priv.PublicKey, partialVerifyResultMessage(&wire), wire.Signature) {
		t.Fatal("validity-bit mutation was accepted")
	}
}

func TestPartialVerifyBatchSignatureBindsCanonicalEntries(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entries := []partialVerifyBatchEntry{
		{Dealer: 3, TranscriptDigest: []byte("digest-3"), Valid: true},
		{Dealer: 7, TranscriptDigest: []byte("digest-7"), Valid: false},
	}
	message := partialVerifyBatchMessage(10, entries)
	signature, err := ecdsa.SignASN1(rand.Reader, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, message, signature) {
		t.Fatal("valid batch signature rejected")
	}
	if bytes.Equal(partialVerifyBatchID(10, entries), partialVerifyBatchID(10, []partialVerifyBatchEntry{entries[1], entries[0]})) {
		t.Fatal("batch ID ignored canonical entry order")
	}
	mutated := append([]partialVerifyBatchEntry(nil), entries...)
	mutated[1].Valid = true
	if ecdsa.VerifyASN1(&priv.PublicKey, partialVerifyBatchMessage(10, mutated), signature) {
		t.Fatal("batch validity mutation was accepted")
	}
	if ecdsa.VerifyASN1(&priv.PublicKey, partialVerifyBatchMessage(11, entries), signature) {
		t.Fatal("batch verifier mutation was accepted")
	}
}

func TestPartialVerifyNodeAddrMapUsesDedicatedNamespace(t *testing.T) {
	cfg := Config{ProtocolNodeAddrs: "10=127.0.0.1:19000,11=127.0.0.1:19001"}
	got, err := partialVerifyNodeAddrMap(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got[10] != "127.0.0.1:31000" || got[11] != "127.0.0.1:31001" {
		t.Fatalf("derived partial addresses=%v", got)
	}
	cfg.PartialVerifyNodeAddrs = "10=127.0.0.1:32000"
	override, err := partialVerifyNodeAddrMap(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if override[10] != "127.0.0.1:32000" {
		t.Fatalf("dedicated partial address override=%v", override)
	}
}

func TestPartialVerifyServiceDecodesResultBatch(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan partialVerifyResultWire, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go servePartialVerifyResults(ctx, listener, out, &wg)
	defer func() {
		cancel()
		_ = listener.Close()
		wg.Wait()
	}()

	wires := []partialVerifyResultWire{
		{Dealer: 3, Verifier: 10, TranscriptDigest: []byte("dealer-3"), Valid: true},
		{Dealer: 7, Verifier: 10, TranscriptDigest: []byte("dealer-7"), Valid: false},
	}
	batch := make([]byte, 0, 512)
	for _, wire := range wires {
		raw, marshalErr := json.Marshal(wire)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		batch = append(batch, raw...)
		batch = append(batch, '\n')
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if written, writeErr := conn.Write(batch); writeErr != nil || written != len(batch) {
		_ = conn.Close()
		t.Fatalf("write batch: bytes=%d/%d err=%v", written, len(batch), writeErr)
	}
	_ = conn.Close()

	for i, want := range wires {
		select {
		case got := <-out:
			if got.Dealer != want.Dealer || got.Verifier != want.Verifier || !bytes.Equal(got.TranscriptDigest, want.TranscriptDigest) {
				t.Fatalf("batch result %d mismatch: got=%+v want=%+v", i, got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for batch result %d", i)
		}
	}
	batchRaw, err := json.Marshal(partialVerifyBatchWire{
		Kind: "partial-verify-batch", Verifier: 10,
		Entries:   []partialVerifyBatchEntry{{Dealer: 9, TranscriptDigest: []byte("dealer-9"), Valid: true}},
		Signature: []byte("batch-signature"),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	batchRaw = append(batchRaw, '\n')
	if written, writeErr := conn.Write(batchRaw); writeErr != nil || written != len(batchRaw) {
		_ = conn.Close()
		t.Fatalf("write envelope: bytes=%d/%d err=%v", written, len(batchRaw), writeErr)
	}
	_ = conn.Close()
	select {
	case got := <-out:
		if got.Dealer != 9 || got.Verifier != 10 || got.BatchCount != 1 || got.BatchIndex != 0 || len(got.BatchSignature) == 0 {
			t.Fatalf("batch envelope expansion mismatch: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for batch envelope result")
	}
}

func TestEncryptedDLogProofBindsPedersenRandomness(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N
	sk, err := GeneratePaillierKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	share := big.NewInt(1234567)
	shareRandomness := big.NewInt(7654321)
	rEnc, err := sk.PublicKey.RandomCoprime()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sk.PublicKey.EncryptWithRandom(share, rEnc)
	if err != nil {
		t.Fatal(err)
	}
	commitment := commitSharePair(curve, share, shareRandomness)
	compKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compPublic := elliptic.MarshalCompressed(curve, compKey.X, compKey.Y)
	blindingCiphertext, blindingRandomness, err := encryptDXTBlinding(curve, compPublic, shareRandomness)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := buildEncryptedDLogProof(
		curve,
		order,
		sk.PublicKey,
		share,
		shareRandomness,
		rEnc,
		commitment,
		ciphertext.Bytes(),
		compPublic,
		blindingCiphertext,
		blindingRandomness,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyEncryptedDLogProof(curve, order, sk.PublicKey, commitment, ciphertext.Bytes(), compPublic, blindingCiphertext, proof) {
		t.Fatal("valid Pedersen/Paillier link proof was rejected")
	}

	tampered := *proof
	tamperedZR := new(big.Int).SetBytes(proof.ZR)
	tamperedZR.Add(tamperedZR, big.NewInt(1)).Mod(tamperedZR, order)
	tampered.ZR = tamperedZR.Bytes()
	if verifyEncryptedDLogProof(curve, order, sk.PublicKey, commitment, ciphertext.Bytes(), compPublic, blindingCiphertext, &tampered) {
		t.Fatal("proof with tampered Pedersen-randomness response was accepted")
	}

	tamperedBlinding := blindingCiphertext
	tamperedBlinding.C1, err = practicalPointAdd(curve, tamperedBlinding.C1, practicalBasePoint(curve, big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	if verifyEncryptedDLogProof(curve, order, sk.PublicKey, commitment, ciphertext.Bytes(), compPublic, tamperedBlinding, proof) {
		t.Fatal("proof accepted a mutated Algorithm 3 blinding ciphertext")
	}
}

func TestCommitmentDegreeCheckRejectsInconsistentEvaluation(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N
	committee := []int{10, 11, 12, 13, 14, 15, 16}
	degree := 2
	coeffS := []*big.Int{big.NewInt(5), big.NewInt(7), big.NewInt(11)}
	coeffR := []*big.Int{big.NewInt(13), big.NewInt(17), big.NewInt(19)}
	commitments := make(map[int][]byte, len(committee))
	for _, rid := range committee {
		x := big.NewInt(int64(rid + 1))
		commitments[rid] = commitSharePair(
			curve,
			evalPoly(coeffS, x, order),
			evalPoly(coeffR, x, order),
		)
	}
	if !verifyCommitmentDegree(curve, commitments, committee, degree) {
		t.Fatal("valid degree-2 commitment evaluations were rejected")
	}
	commitments[committee[len(committee)-1]] = commitSharePair(curve, big.NewInt(23), big.NewInt(29))
	if verifyCommitmentDegree(curve, commitments, committee, degree) {
		t.Fatal("inconsistent commitment evaluation passed degree check")
	}
}

func TestDXTBackendUsesHighThresholdDegree(t *testing.T) {
	committee := []int{10, 11, 12, 13, 14, 15, 16}
	b, err := NewDXTBackend(
		[]int{0, 1, 2, 3, 4, 5, 6}, committee, 2,
		nil, nil, nil, nil, nil, nil, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if b.f != 2 || b.sharingDegree != 4 {
		t.Fatalf("threshold separation failed: f=%d degree=%d", b.f, b.sharingDegree)
	}
	bLarger, err := NewDXTBackend(
		[]int{0, 1, 2, 3, 4, 5, 6, 7}, []int{10, 11, 12, 13, 14, 15, 16, 17}, 2,
		nil, nil, nil, nil, nil, nil, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if bLarger.sharingDegree != 5 {
		t.Fatalf("non-minimal committee degree=%d, want n-f-1=5", bLarger.sharingDegree)
	}

	curve := elliptic.P256()
	order := curve.Params().N
	coeffS := []*big.Int{big.NewInt(5), big.NewInt(7), big.NewInt(11), big.NewInt(13), big.NewInt(17)}
	coeffR := []*big.Int{big.NewInt(19), big.NewInt(23), big.NewInt(29), big.NewInt(31), big.NewInt(37)}
	commitments := make(map[int][]byte, len(committee))
	for _, rid := range committee {
		x := big.NewInt(int64(rid + 1))
		commitments[rid] = commitSharePair(
			curve,
			evalPoly(coeffS, x, order),
			evalPoly(coeffR, x, order),
		)
	}
	if !verifyCommitmentDegree(curve, commitments, committee, b.sharingDegree) {
		t.Fatal("valid degree-2f commitment evaluations were rejected")
	}
	if verifyCommitmentDegree(curve, commitments, committee, b.f) {
		t.Fatal("degree-2f commitments unexpectedly passed the old degree-f check")
	}

	if _, err := NewDXTBackend(
		[]int{0, 1, 2, 3}, []int{10, 11, 12, 13}, 2,
		nil, nil, nil, nil, nil, nil, "", "",
	); err == nil {
		t.Fatal("accepted a committee too small for degree-2f sharing")
	}
}

func TestDXTVerificationRejectsProofAndACKMutation(t *testing.T) {
	protoIDs := []int{0, 1, 2, 3, 10, 11, 12, 13}
	cfg := Config{
		SID:                  "test-dxt-mutations",
		OldCommittee:         []int{0, 1, 2, 3},
		NewCommittee:         []int{10, 11, 12, 13},
		F:                    1,
		PaillierBits:         2048,
		ProtocolNodeAddrs:    buildAddrCSV(protoIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(protoIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	// Force one receiver onto the VE lane so this mutation test covers
	// both branches even when local ACK synthesis is available.
	delete(dxt.recipientSignPriv, 13)
	transcript, _, err := dxt.Deal(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(transcript.Signatures) + len(transcript.Ciphertexts); got != len(cfg.NewCommittee) {
		t.Fatalf("ACK/VE lanes cover %d receivers, want %d", got, len(cfg.NewCommittee))
	}
	for rid := range transcript.Signatures {
		if _, duplicated := transcript.Ciphertexts[rid]; duplicated {
			t.Fatalf("receiver %d appears in both ACK and VE lanes", rid)
		}
	}
	if !dxt.VerifyTranscript(10, transcript) {
		t.Fatal("valid transcript was rejected")
	}
	for _, verifier := range cfg.OldCommittee {
		if !dxt.PartialVerify(verifier, transcript) {
			t.Fatalf("valid partial verification failed for old node %d", verifier)
		}
	}
	if dxt.PartialVerify(9999, transcript) {
		t.Fatal("unknown partial verifier was accepted")
	}

	var veRecipient int
	for rid := range transcript.Ciphertexts {
		veRecipient = rid
		break
	}
	if veRecipient == 0 {
		t.Fatal("test transcript did not contain a VE lane")
	}
	proofBytes := append([]byte(nil), transcript.Proofs[veRecipient]...)
	var proof EncryptedDLogProof
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatal(err)
	}
	proof.ZR = append([]byte(nil), proof.ZR...)
	proof.ZR[len(proof.ZR)-1] ^= 1
	transcript.Proofs[veRecipient], err = json.Marshal(&proof)
	if err != nil {
		t.Fatal(err)
	}
	if dxt.VerifyTranscript(10, transcript) {
		t.Fatal("transcript with mutated VE proof was accepted")
	}
	transcript.Proofs[veRecipient] = proofBytes

	var ackRecipient int
	for rid := range transcript.Signatures {
		ackRecipient = rid
		break
	}
	if ackRecipient == 0 {
		t.Fatal("test transcript did not contain an ACK lane")
	}
	transcript.Signatures[ackRecipient] = append([]byte(nil), transcript.Signatures[ackRecipient]...)
	transcript.Signatures[ackRecipient][0] ^= 1
	if dxt.VerifyTranscript(10, transcript) {
		t.Fatal("transcript with mutated ACK was accepted")
	}
}
