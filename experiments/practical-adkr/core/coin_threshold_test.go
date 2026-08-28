package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	dmvba "dumbomvba_go/core"
)

func TestThresholdCoinHighThresholdAndUniqueRecovery(t *testing.T) {
	old := []int{0, 1, 2, 3, 4, 5, 6}
	keys, err := generateThresholdCoinKeys(old, 2)
	if err != nil {
		t.Fatal(err)
	}
	if keys.threshold != 5 {
		t.Fatalf("coin threshold=%d, want n-f=5", keys.threshold)
	}
	digest := []byte("threshold-coin-test-digest")
	first := recoverCoinFromNodeIDs(t, keys, digest, []int{0, 1, 2, 3, 4})
	second := recoverCoinFromNodeIDs(t, keys, digest, []int{2, 3, 4, 5, 6})
	if !bytes.Equal(first, second) {
		t.Fatal("different valid high-threshold subsets recovered different BLS signatures")
	}

	combiner, err := keys.signer(0)
	if err != nil {
		t.Fatal(err)
	}
	const highDomain = "PD_STORED"
	validShare, err := combiner.Sign(highDomain, digest)
	if err != nil {
		t.Fatal(err)
	}
	forgedShare := append([]byte(nil), validShare...)
	forgedShare[len(forgedShare)-1] ^= 1
	if combiner.Verify(keys.nodeIndex[0], highDomain, digest, forgedShare) {
		t.Fatal("accepted a forged threshold coin share")
	}
	insufficient := make(map[int][]byte, keys.threshold-1)
	for _, nodeID := range old[:keys.threshold-1] {
		signer, _ := keys.signer(nodeID)
		share, signErr := signer.Sign(highDomain, digest)
		if signErr != nil {
			t.Fatal(signErr)
		}
		insufficient[keys.nodeIndex[nodeID]] = share
	}
	if _, err := combiner.Recover(highDomain, digest, insufficient); err == nil {
		t.Fatal("recovered threshold coin signature with fewer than n-f shares")
	}
}

func TestStrictThresholdCoinSetupLoadsOnlyLocalShare(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", dir)
	old := []int{0, 1, 2, 3}
	cfg := Config{
		SID:              "strict-coin-setup",
		OldCommittee:     old,
		F:                1,
		MVBALocalNodeIDs: "2",
		StrictNetwork:    true,
	}
	keys, err := loadOrCreateThresholdCoinKeys(cfg, old)
	if err != nil {
		t.Fatal(err)
	}
	if keys.threshold != 3 || len(keys.privateShare) != 1 {
		t.Fatalf("unexpected strict key ownership: threshold=%d private=%d", keys.threshold, len(keys.privateShare))
	}
	if _, ok := keys.privateShare[2]; !ok {
		t.Fatal("strict threshold coin did not load the local node's share")
	}
	if _, err := keys.signer(1); err == nil {
		t.Fatal("strict threshold coin created a signer for a non-local node")
	}
	publicPath := thresholdCoinPublicPath(dir, old, cfg.F)
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicRaw, []byte(`"share":`)) {
		t.Fatal("threshold coin public artifact contains a private share field")
	}
	privateInfo, err := os.Stat(thresholdCoinPrivatePath(publicPath, 2))
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("threshold coin private artifact mode=%o, want 600", privateInfo.Mode().Perm())
	}
}

func TestInternalMVBAEndpointConfigMapsActualNodeIDs(t *testing.T) {
	old := []int{10, 20, 30, 40}
	indexByNode := map[int]int{10: 0, 20: 1, 30: 2, 40: 3}
	cfg := Config{
		MVBANodeAddrs:    "10=127.0.0.1:31010,20=127.0.0.1:31020,30=127.0.0.1:31030,40=127.0.0.1:31040",
		MVBALocalNodeIDs: "20,40",
	}
	internal, local, err := internalMVBAEndpointConfig(cfg, old, indexByNode)
	if err != nil {
		t.Fatal(err)
	}
	if internal.MVBANodeAddrs != "0=127.0.0.1:31010,1=127.0.0.1:31020,2=127.0.0.1:31030,3=127.0.0.1:31040" {
		t.Fatalf("unexpected internal addresses: %s", internal.MVBANodeAddrs)
	}
	if internal.MVBALocalNodeIDs != "1,3" {
		t.Fatalf("unexpected internal local ids: %s", internal.MVBALocalNodeIDs)
	}
	if _, ok := local[1]; !ok {
		t.Fatal("actual node 20 was not mapped to internal node 1")
	}
	if _, ok := local[3]; !ok {
		t.Fatal("actual node 40 was not mapped to internal node 3")
	}

	cfg.MVBALocalNodeIDs = "99"
	if _, _, err := internalMVBAEndpointConfig(cfg, old, indexByNode); err == nil {
		t.Fatal("accepted a local MVBA node outside the old committee")
	}
}

func TestThresholdCoinTCPMulticastConsistentWithLateCoinEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", dir)
	old := []int{0, 1, 2, 3}
	protocolAddresses := buildAddrCSV(old, nextTestBase(20))
	coinAddresses := buildAddrCSV(old, nextTestBase(20))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type process struct {
		cfg     Config
		keys    *thresholdCoinKeySet
		service *thresholdCoinService
	}
	processes := make([]process, 0, len(old))
	for _, nodeID := range old {
		cfg := Config{
			SID:                  "threshold-coin-tcp",
			Epoch:                9,
			OldCommittee:         old,
			F:                    1,
			Kappa:                2,
			MVBALocalNodeIDs:     fmt.Sprintf("%d", nodeID),
			ProtocolNodeAddrs:    protocolAddresses,
			ProtocolLocalNodeIDs: fmt.Sprintf("%d", nodeID),
			CoinNodeAddrs:        coinAddresses,
			RouteSendTimeout:     300 * time.Millisecond,
			StrictNetwork:        true,
		}
		keys, err := loadOrCreateThresholdCoinKeys(cfg, old)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys.privateShare) != 1 {
			t.Fatalf("node %d loaded %d private shares", nodeID, len(keys.privateShare))
		}
		if _, ok := keys.privateShare[nodeID]; !ok {
			t.Fatalf("node %d loaded a different node's private share", nodeID)
		}
		service, err := startThresholdCoinService(ctx, cfg, old, keys.privateShare)
		if err != nil {
			t.Fatal(err)
		}
		processes = append(processes, process{cfg: cfg, keys: keys, service: service})
	}
	defer func() {
		for _, process := range processes {
			process.service.close()
		}
	}()
	type result struct {
		selected  []int
		signature []byte
		err       error
	}
	results := make(chan result, len(processes))
	var wg sync.WaitGroup
	for processIndex, process := range processes {
		processIndex := processIndex
		process := process
		wg.Add(1)
		go func() {
			defer wg.Done()
			if processIndex == len(processes)-1 {
				time.Sleep(750 * time.Millisecond)
			}
			selected, signature, err := runThresholdCoin(ctx, process.cfg, old, []int{0, 1, 2}, 2, process.keys, process.service)
			results <- result{selected: selected, signature: signature, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var wantSelection string
	var wantSignature []byte
	var processErrors []string
	for result := range results {
		if result.err != nil {
			processErrors = append(processErrors, result.err.Error())
			continue
		}
		selection := fmt.Sprint(result.selected)
		if wantSelection == "" {
			wantSelection = selection
			wantSignature = append([]byte(nil), result.signature...)
			continue
		}
		if selection != wantSelection || !bytes.Equal(result.signature, wantSignature) {
			t.Fatalf("inconsistent network coin output: selection=%s want=%s signature_equal=%v", selection, wantSelection, bytes.Equal(result.signature, wantSignature))
		}
	}
	if len(processErrors) > 0 {
		t.Fatalf("threshold coin process errors: %v", processErrors)
	}
	if strings.TrimSpace(wantSelection) == "" || len(wantSignature) == 0 {
		t.Fatal("threshold coin network test produced no output")
	}
}

func TestThresholdCoinInputBindsEpoch(t *testing.T) {
	old := []int{0, 1, 2, 3}
	a, err := thresholdCoinInputDigest("sid", 1, old, []int{2, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := thresholdCoinInputDigest("sid", 2, old, []int{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("threshold coin input did not bind the reconfiguration epoch")
	}
	if _, err := thresholdCoinInputDigest("sid", 1, old, []int{0, 1, 1}); err == nil {
		t.Fatal("threshold coin accepted a duplicate decided dealer")
	}
}

func recoverCoinFromNodeIDs(t *testing.T, keys *thresholdCoinKeySet, digest []byte, nodeIDs []int) []byte {
	t.Helper()
	var combiner dmvba.ThresholdSigner
	shares := make(map[int][]byte, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		signer, err := keys.signer(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if combiner == nil {
			combiner = signer
		}
		share, err := signer.Sign(thresholdCoinBLSDomain, digest)
		if err != nil {
			t.Fatal(err)
		}
		index := keys.nodeIndex[nodeID]
		if !combiner.Verify(index, thresholdCoinBLSDomain, digest, share) {
			t.Fatalf("valid coin share for node %d failed verification", nodeID)
		}
		shares[index] = share
	}
	recovered, err := combiner.Recover(thresholdCoinBLSDomain, digest, shares)
	if err != nil {
		t.Fatal(err)
	}
	if !combiner.VerifyRecovered(thresholdCoinBLSDomain, digest, recovered) {
		t.Fatal("recovered threshold coin signature failed verification")
	}
	return recovered
}
