package core

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

func TestStrictCompSetupLoadsOnlyLocalPrivateKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", dir)
	committee := []int{10, 11, 12, 13}
	cfg := Config{StrictNetwork: true, ProtocolLocalNodeIDs: "11", NewCommittee: committee}
	keys, err := loadOrCreatePracticalCompKeys(cfg, committee)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.public) != len(committee) || len(keys.private) != 1 || keys.private[11] == nil {
		t.Fatalf("unexpected CompProve key ownership: public=%d private=%d", len(keys.public), len(keys.private))
	}
	publicPath := practicalCompPublicPath(dir, committee)
	raw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"scalar"`)) {
		t.Fatal("CompProve public artifact contains private scalar")
	}
	info, err := os.Stat(practicalCompPrivatePath(publicPath, 11))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CompProve private artifact mode=%o, want 600", info.Mode().Perm())
	}
}

func TestCompKeyReadinessWaitsForQuorum(t *testing.T) {
	committee := []int{10, 11, 12, 13}
	cfg := Config{
		SID: "comp-readiness", Epoch: 7, F: 1,
		CompNodeAddrs: buildAddrCSV(committee, nextTestBase(100)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keys := map[int]*big.Int{committee[0]: big.NewInt(1)}
	first, err := startCompKeyService(ctx, cfg, committee, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()

	ready := make(chan error, 1)
	go func() { ready <- waitCompKeyServiceReady(ctx, cfg, committee, first) }()
	select {
	case err := <-ready:
		t.Fatalf("readiness returned before quorum: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	services := make([]*compKeyService, 0, 2)
	for _, id := range committee[1:3] {
		service, startErr := startCompKeyService(ctx, cfg, committee, map[int]*big.Int{id: big.NewInt(1)})
		if startErr != nil {
			t.Fatal(startErr)
		}
		services = append(services, service)
		defer service.close()
	}
	if err := <-ready; err != nil {
		t.Fatalf("wait for CompProve quorum: %v", err)
	}
}

func TestCompKeyMulticastWithReceiverLocalSecrets(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	protoIDs := append(append([]int(nil), old...), newCommittee...)
	cfg := Config{
		SID:                  "comp-multicast-local-secrets",
		Epoch:                4,
		OldCommittee:         old,
		NewCommittee:         newCommittee,
		F:                    1,
		PaillierBits:         2048,
		ProtocolNodeAddrs:    buildAddrCSV(protoIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(protoIDs),
		CompNodeAddrs:        buildAddrCSV(newCommittee, nextTestBase(100)),
	}
	dxt := setupDXTBackend(t, cfg)
	compKeys, err := generatePracticalCompKeys(newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if err := dxt.setCompPublicKeys(compKeys.public); err != nil {
		t.Fatal(err)
	}
	transcripts := make(map[int]*DXTTranscript, 2)
	allShares := make(map[int]map[int]SharePair, 2)
	for _, dealer := range old[:2] {
		transcript, shares, dealErr := dxt.Deal(context.Background(), dealer, nil)
		if dealErr != nil {
			t.Fatal(dealErr)
		}
		transcripts[dealer] = transcript
		allShares[dealer] = shares
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	type process struct {
		id      int
		cfg     Config
		keys    *practicalCompKeySet
		service *compKeyService
	}
	processes := make([]process, 0, len(newCommittee))
	for _, id := range newCommittee {
		processCfg := cfg
		processCfg.ProtocolLocalNodeIDs = ""
		view := &practicalCompKeySet{
			nodeIDs: append([]int(nil), compKeys.nodeIDs...),
			public:  compKeys.public,
			private: map[int]*big.Int{id: new(big.Int).Set(compKeys.private[id])},
		}
		service, serviceErr := startCompKeyService(ctx, processCfg, newCommittee, view.private)
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		defer service.close()
		processes = append(processes, process{id: id, cfg: processCfg, keys: view, service: service})
	}

	type result struct {
		id         int
		cfg        Config
		secret     []byte
		group      []byte
		public     map[int][]byte
		completion CompKeyCompletionCertificate
		err        error
	}
	results := make(chan result, len(processes))
	var wg sync.WaitGroup
	for _, process := range processes {
		process := process
		wg.Add(1)
		go func() {
			defer wg.Done()
			localShares := make(map[int]map[int]SharePair, len(allShares))
			for dealer, shares := range allShares {
				localShares[dealer] = map[int]SharePair{process.id: shares[process.id]}
			}
			private := map[int]*PaillierPrivateKey{process.id: dxt.recipientPriv[process.id]}
			secrets, group, public, completions, runErr := runCompKeyDerivationMulticast(
				ctx, process.cfg, newCommittee, old[:2], transcripts, localShares,
				private, process.keys, process.service, dxt,
			)
			results <- result{
				id: process.id, cfg: process.cfg, secret: secrets[process.id], group: group, public: public,
				completion: completions[process.id], err: runErr,
			}
		}()
	}
	wg.Wait()
	close(results)
	var group []byte
	for output := range results {
		if output.err != nil {
			t.Fatalf("CompProve process %d failed: %v", output.id, output.err)
		}
		if len(output.secret) == 0 || len(output.public) != len(newCommittee) {
			t.Fatalf("CompProve process %d returned incomplete output", output.id)
		}
		if group == nil {
			group = append([]byte(nil), output.group...)
		} else if !bytes.Equal(group, output.group) {
			t.Fatal("CompProve processes derived different group public keys")
		}
		if !bytes.Equal(commitScalar(elliptic.P256(), new(big.Int).SetBytes(output.secret)), output.public[output.id]) {
			t.Fatalf("CompProve process %d secret/public output mismatch", output.id)
		}
		if !verifyCompKeyCompletionCertificate(output.cfg, output.completion, dxt.recipientSignPub[output.id]) {
			t.Fatalf("CompProve process %d returned an invalid completion certificate", output.id)
		}
		if output.completion.Threshold != len(newCommittee)-cfg.F || len(output.completion.ShareDigests) != len(newCommittee)-cfg.F {
			t.Fatalf("CompProve process %d completion threshold mismatch", output.id)
		}
		mutated := output.completion
		mutated.GroupPublicKey = append([]byte(nil), mutated.GroupPublicKey...)
		mutated.GroupPublicKey[0] ^= 1
		if verifyCompKeyCompletionCertificate(output.cfg, mutated, dxt.recipientSignPub[output.id]) {
			t.Fatalf("CompProve process %d completion accepted a mutated group key", output.id)
		}
	}
}

func TestCompProofBindsMixedACKAndVELanes(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N
	nodeID := 10
	paillier, err := GeneratePaillierKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	compPrivate, err := rand.Int(rand.Reader, order)
	if err != nil {
		t.Fatal(err)
	}
	compPublic := practicalBasePoint(curve, compPrivate)

	ackShare := SharePair{S: big.NewInt(17), SR: big.NewInt(29)}
	ackTranscript := &DXTTranscript{
		Dealer:      1,
		Commitments: map[int][]byte{nodeID: commitSharePair(curve, ackShare.S, ackShare.SR)},
		Signatures:  map[int][]byte{nodeID: []byte("ack")},
	}

	veS, veR := big.NewInt(31), big.NewInt(43)
	paillierRandomness, err := paillier.PublicKey.RandomCoprime()
	if err != nil {
		t.Fatal(err)
	}
	paillierCiphertext, err := paillier.PublicKey.EncryptWithRandom(veS, paillierRandomness)
	if err != nil {
		t.Fatal(err)
	}
	blindingCiphertext, _, err := encryptDXTBlinding(curve, compPublic, veR)
	if err != nil {
		t.Fatal(err)
	}
	veTranscript := &DXTTranscript{
		Dealer:              2,
		Commitments:         map[int][]byte{nodeID: commitSharePair(curve, veS, veR)},
		Ciphertexts:         map[int][]byte{nodeID: paillierCiphertext.Bytes()},
		BlindingCiphertexts: map[int]DXTBlindingCiphertext{nodeID: blindingCiphertext},
	}
	transcripts := map[int]*DXTTranscript{1: ackTranscript, 2: veTranscript}
	selectedDigest, selected, err := compSelectedDigest([]int{2, 1}, transcripts)
	if err != nil {
		t.Fatal(err)
	}
	localShares := map[int]map[int]SharePair{1: {nodeID: ackShare}}
	share, secret, err := compProve(
		"comp-mixed", 7, nodeID, selected, selectedDigest, transcripts,
		localShares, paillier, compPrivate, compPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantSecret := new(big.Int).Add(ackShare.S, veS)
	wantSecret.Mod(wantSecret, order)
	if secret.Cmp(wantSecret) != 0 {
		t.Fatalf("mixed CompProve secret=%s want=%s", secret, wantSecret)
	}
	if !verifyCompPublicKeyShare("comp-mixed", 7, share, selected, selectedDigest, transcripts, compPublic) {
		t.Fatal("valid mixed ACK/VE CompProof was rejected")
	}

	mutated := share
	mutated.PKShare, err = practicalPointAdd(curve, share.PKShare, practicalBasePoint(curve, big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	if verifyCompPublicKeyShare("comp-mixed", 7, mutated, selected, selectedDigest, transcripts, compPublic) {
		t.Fatal("CompProof accepted a mutated public key share")
	}
	wrongDigest := append([]byte(nil), selectedDigest...)
	wrongDigest[0] ^= 1
	if verifyCompPublicKeyShare("comp-mixed", 7, share, selected, wrongDigest, transcripts, compPublic) {
		t.Fatal("CompProof was not bound to the selected transcript digest")
	}

	mutatedTranscript := *veTranscript
	mutatedTranscript.BlindingCiphertexts = map[int]DXTBlindingCiphertext{nodeID: blindingCiphertext}
	mutatedCiphertext := mutatedTranscript.BlindingCiphertexts[nodeID]
	mutatedCiphertext.C1, err = practicalPointAdd(curve, mutatedCiphertext.C1, practicalBasePoint(curve, big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	mutatedTranscript.BlindingCiphertexts[nodeID] = mutatedCiphertext
	mutatedTranscripts := map[int]*DXTTranscript{1: ackTranscript, 2: &mutatedTranscript}
	if verifyCompPublicKeyShare("comp-mixed", 7, share, selected, selectedDigest, mutatedTranscripts, compPublic) {
		t.Fatal("CompProof accepted a mutated VE blinding ciphertext")
	}
}

func TestInterpolateCompPublicKeysUsesHighThreshold(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N
	committee := []int{10, 11, 12, 13}
	coefficients := []*big.Int{big.NewInt(101), big.NewInt(7), big.NewInt(13)}
	shares := make(map[int]CompPublicKeyShare, 3)
	for _, id := range committee[:3] {
		scalar := evalPoly(coefficients, big.NewInt(int64(id+1)), order)
		shares[id] = CompPublicKeyShare{NodeID: id, PKShare: practicalBasePoint(curve, scalar)}
	}
	group, all, err := interpolateCompPublicKeys(committee, shares, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(group, practicalBasePoint(curve, coefficients[0])) {
		t.Fatal("interpolated CompProve group key is incorrect")
	}
	for _, id := range committee {
		want := practicalBasePoint(curve, evalPoly(coefficients, big.NewInt(int64(id+1)), order))
		if !bytes.Equal(all[id], want) {
			t.Fatalf("interpolated public share for node %d is incorrect", id)
		}
	}
	if _, _, err := interpolateCompPublicKeys(committee, shares, 4); err == nil {
		t.Fatal("interpolation accepted fewer than n-f shares")
	}

	if _, err := json.Marshal(all); err != nil {
		t.Fatal(err)
	}
}
