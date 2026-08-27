package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestValidateCVEpochConfigRequiresDeployableProfile(t *testing.T) {
	base := NormalizeConfig(Config{
		SID:                "cv-epoch-config",
		OldCommittee:       []int{0, 1, 2, 3},
		NewCommittee:       []int{4, 5, 6, 7},
		FOld:               1,
		FNew:               1,
		AgreementTransport: "tcp-distributed",
		LocalNodeIDs:       []int{0},
		CVPublicKeyDir:     "/keys/public",
		CVLocalSecretDir:   "/keys/private-0",
		CVLocalReceiverIDs: []int{4},
		ArtifactCacheDir:   "/state/node-0",
	})
	if err := validateCVEpochConfig(base); err != nil {
		t.Fatalf("valid CV epoch config rejected: %v", err)
	}
	compact := base
	compact.APVSSFallbackProfile = apvssFallbackCompactBatchProfile
	if err := validateCVEpochConfig(compact); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("compact profile crossed production admission without opt-in: %v", err)
	}
	compact.AllowExperimentalAPVSS = true
	compact.APVSSBenchmarkFallbackCount = compact.FNew
	if err := validateCVEpochConfig(compact); err != nil {
		t.Fatalf("explicit experimental compact profile rejected: %v", err)
	}
	forced := base
	forced.APVSSBenchmarkFallbackCount = 1
	if err := validateCVEpochConfig(forced); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("forced fallback scheduling crossed experimental gate: %v", err)
	}
	waitAll := base
	waitAll.APVSSBenchmarkWaitAllACKs = true
	if err := validateCVEpochConfig(waitAll); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("wait-all ACK scheduling crossed experimental gate: %v", err)
	}
	waitAll.AllowExperimentalAPVSS = true
	if err := validateCVEpochConfig(waitAll); err != nil {
		t.Fatalf("explicit experimental wait-all ACK mode rejected: %v", err)
	}
	full := base
	full.APVSSMode = APVSSModeFullPublicVE
	if err := validateCVEpochConfig(full); err == nil || !strings.Contains(err.Error(), "backend gate") {
		t.Fatalf("full proof prototype crossed backend gate without opt-in: %v", err)
	}
	full.AllowExperimentalAPVSS = true
	if err := validateCVEpochConfig(full); err != nil {
		t.Fatalf("explicit experimental full proof mode rejected: %v", err)
	}
	full.APVSSBenchmarkWaitAllACKs = true
	if err := validateCVEpochConfig(full); err == nil || !strings.Contains(err.Error(), "does not use ACK/fallback") {
		t.Fatalf("full proof mode accepted ACK controls: %v", err)
	}

	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"old node", func(c *Config) { c.LocalNodeIDs = []int{0, 1} }, "one local old node"},
		{"public keys", func(c *Config) { c.CVPublicKeyDir = "" }, "public key directory"},
		{"secret keys", func(c *Config) { c.CVLocalSecretDir = "" }, "secret key directory"},
		{"same key dir", func(c *Config) { c.CVLocalSecretDir = c.CVPublicKeyDir }, "separate"},
		{"receiver", func(c *Config) { c.CVLocalReceiverIDs = nil }, "local receiver"},
		{"store", func(c *Config) { c.ArtifactCacheDir = "" }, "artifact store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.edit(&cfg)
			err := validateCVEpochConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateConfigRejectsLegacyAblationMode(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	cfg.AblationMode = "no-agclock"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("CV V2 accepted legacy no-agclock ablation mode")
	}
}

func TestNormalizeConfigDefaultsToFeldmanBatchFallback(t *testing.T) {
	cfg := NormalizeConfig(Config{FOld: 1, FNew: 1})
	if cfg.APVSSMode != APVSSModeACKFallback ||
		cfg.APVSSFullProofProfile != APVSSFullProofExact ||
		cfg.APVSSFallbackProfile != apvssFallbackFeldmanBatchProfile || cfg.AllowExperimentalAPVSS {
		t.Fatalf("default APVSS mode/full/fallback = %q/%q/%q experimental=%t",
			cfg.APVSSMode, cfg.APVSSFullProofProfile, cfg.APVSSFallbackProfile, cfg.AllowExperimentalAPVSS)
	}
}

func TestACKFallbackProductionAdmissionV1(t *testing.T) {
	base := Config{APVSSMode: APVSSModeACKFallback}

	production := base
	production.APVSSFallbackProfile = apvssFallbackFeldmanBatchProfile
	production.AllowExperimentalAPVSS = false
	if err := validateAPVSSProductionAdmission(production); err != nil {
		t.Fatalf("production Feldman fallback was rejected: %v", err)
	}

	for _, profile := range []string{
		apvssFallbackExactLaneProfile,
		apvssFallbackCompactBatchProfile,
	} {
		experimental := base
		experimental.APVSSFallbackProfile = profile
		experimental.AllowExperimentalAPVSS = false
		if err := validateAPVSSProductionAdmission(experimental); err == nil {
			t.Fatalf("fallback profile %q bypassed experimental admission", profile)
		}
		experimental.AllowExperimentalAPVSS = true
		if err := validateAPVSSProductionAdmission(experimental); err != nil {
			t.Fatalf("explicitly admitted fallback profile %q was rejected: %v", profile, err)
		}
	}
}

func TestValidateConfigRejectsUnknownFullProofProfile(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID: "invalid-full-proof-profile", OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{4, 5, 6, 7}, FOld: 1, FNew: 1,
		APVSSMode: APVSSModeFullPublicVE, APVSSFullProofProfile: "unknown",
	})
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "full-public-ve proof profile") {
		t.Fatalf("unknown full proof profile validation error = %v", err)
	}
}

func TestValidateConfigRejectsUnknownAPVSSMode(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID: "invalid-apvss-mode", OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{4, 5, 6, 7}, FOld: 1, FNew: 1,
		APVSSMode: "unknown",
	})
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "invalid APVSS mode") {
		t.Fatalf("unknown APVSS mode validation error = %v", err)
	}
}

func TestCVReceiptExchangeReturnsCommonKeyAndLocalShares(t *testing.T) {
	cfg, leafContext, receiverSecrets, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(context.Background(), cfg, &leafContext, node, transport, router, store)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	type result struct {
		shares   map[int][]byte
		receipts map[int][]byte
		key      []byte
		err      error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			shares, receipts, key, exchangeErr := services[i].ExchangeReceipts(
				ctx, agg, cfg.NewCommittee, map[int]fr.Element{i: receiverSecrets[i]},
			)
			results <- result{shares: shares, receipts: receipts, key: key, err: exchangeErr}
		}()
	}
	first, second := <-results, <-results
	for _, got := range []result{first, second} {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.shares) != 1 || len(got.receipts) < leafContext.sharingDegree+1 {
			t.Fatalf("local shares/verified receipts = %d/%d", len(got.shares), len(got.receipts))
		}
	}
	if !bytes.Equal(first.key, second.key) {
		t.Fatal("valid receipt subsets produced different threshold public keys")
	}
}

func TestRestrictThresholdSignerToLocalMembers(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	cfg.runtime.lockSigner.restrictSigningTo([]int{0})
	if _, err := cfg.runtime.lockSigner.SignShare(0, "test", digest); err != nil {
		t.Fatalf("local signer rejected: %v", err)
	}
	if _, err := cfg.runtime.lockSigner.SignShare(1, "test", digest); err == nil {
		t.Fatal("restricted signer signed for a non-local holder")
	}
}

func TestCVMaterializedAggRLOWitnessRoundTrip(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvMaterializedAggRLOWitnessCanonicalBytes(materialized.rlo)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeMaterializedAggRLOWitness(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, materialized.rlo.Digest) ||
		!bytes.Equal(digestAggHeaderForLock(decoded.Header), digestAggHeaderForLock(materialized.rlo.Header)) {
		t.Fatal("materialized AggRLO witness changed its statement")
	}
	if _, err := cvDecodeMaterializedAggRLOWitness(append(wire, 0), cfg); err == nil {
		t.Fatal("accepted materialized AggRLO witness with trailing bytes")
	}

	tampered := cloneAggRLO(materialized.rlo)
	tampered.Lock.Certificate[0] ^= 1
	tampered.Digest = digestAggRLO(*tampered)
	tamperedWire, err := cvMaterializedAggRLOWitnessCanonicalBytes(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeMaterializedAggRLOWitness(tamperedWire, cfg); err == nil {
		t.Fatal("accepted materialized AggRLO witness with an invalid certificate")
	}
	if decoded.Lock.Threshold != materialized.rlo.Lock.Threshold || !bytes.Equal(decoded.Lock.Certificate, materialized.rlo.Lock.Certificate) {
		t.Fatal("compact AggRLO witness changed the recovered ARC certificate")
	}
}

func TestCVBuildEpochContextAndRandomDealerLeaf(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	dirs := generateCVReceiverKeysForTest(t, cfg.SID, cfg.NewCommittee)
	material, err := cvLoadReceiverKeyMaterial(
		dirs.public, dirs.secret, cfg.SID, cfg.NewCommittee, []int{cfg.NewCommittee[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(leafContext.dealerSetPolicy, material.registryDigest) {
		t.Fatal("CV epoch context does not bind receiver ID registry digest")
	}
	leaf, err := cvRandomDealerLeaf(leafContext, cfg.LocalNodeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.dealerID != uint64(cfg.LocalNodeIDs[0]) || leaf.context.proofProfile != cvLeafStructuralProofProfile || leaf.hasLeafNIZK {
		t.Fatal("random CV dealer leaf has the wrong dealer or proof profile")
	}
	if err := cvVerifyLeaf(&leafContext, leaf); err != nil {
		t.Fatalf("random CV dealer leaf rejected: %v", err)
	}
}

func TestCVBuildEpochFullPublicVEPrototype(t *testing.T) {
	if testing.Short() {
		t.Skip("experimental full-public VE prototype")
	}
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.APVSSMode = APVSSModeFullPublicVE
	dirs := generateCVReceiverKeysForTest(t, cfg.SID, cfg.NewCommittee)
	material, err := cvLoadReceiverKeyMaterial(
		dirs.public, dirs.secret, cfg.SID, cfg.NewCommittee, []int{cfg.NewCommittee[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvBuildEpochLeafContext(cfg, material); err == nil || !strings.Contains(err.Error(), "backend gate") {
		t.Fatalf("direct full-public context construction bypassed experimental admission: %v", err)
	}
	cfg.AllowExperimentalAPVSS = true
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		t.Fatal(err)
	}
	if leafContext.proofProfile != cvLeafGrothProofProfile {
		t.Fatalf("full mode proof profile = %q", leafContext.proofProfile)
	}
	leaf, _, err := cvRandomDealerLeafWithWitness(leafContext, cfg.LocalNodeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.hasLeafNIZK || leaf.proof == nil {
		t.Fatal("full mode generated no public proof")
	}
	proofWire, err := cvLeafProofCanonicalBytes(leaf.proof)
	if err != nil || len(proofWire) == 0 {
		t.Fatalf("full mode proof bytes = %d, err=%v", len(proofWire), err)
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLeaf(wire, &leafContext)
	if err != nil {
		t.Fatalf("holder rejected full proof leaf: %v", err)
	}
	if err := cvVerifyLeaf(&leafContext, decoded); err != nil {
		t.Fatalf("full proof leaf verification failed: %v", err)
	}
	structuralContext := leafContext
	structuralContext.proofProfile = cvLeafStructuralProofProfile
	if _, err := cvDecodeLeaf(wire, &structuralContext); err == nil {
		t.Fatal("full proof leaf replayed into ACK/fallback context")
	}
}

func TestCVBuildEpochFullCompactPublicVEPrototype(t *testing.T) {
	if testing.Short() {
		t.Skip("experimental compact full-public VE prototype")
	}
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.APVSSMode = APVSSModeFullPublicVE
	cfg.APVSSFullProofProfile = APVSSFullProofCompactBatch
	cfg.AllowExperimentalAPVSS = true
	dirs := generateCVReceiverKeysForTest(t, cfg.SID, cfg.NewCommittee)
	material, err := cvLoadReceiverKeyMaterial(
		dirs.public, dirs.secret, cfg.SID, cfg.NewCommittee, []int{cfg.NewCommittee[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		t.Fatal(err)
	}
	if leafContext.proofProfile != cvLeafFullCompactProofProfile {
		t.Fatalf("full compact mode proof profile = %q", leafContext.proofProfile)
	}
	leaf, witness, err := cvRandomDealerLeafWithWitness(leafContext, cfg.LocalNodeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof == nil {
		t.Fatal("full compact mode generated the wrong proof capability")
	}
	if got := apvssCompactLinkReceiverIndices(leaf.compactProof.link); len(got) != len(cfg.NewCommittee) {
		t.Fatalf("full compact proof covers %d receivers, want %d", len(got), len(cfg.NewCommittee))
	} else {
		for i, receiver := range got {
			if receiver != i+1 {
				t.Fatalf("full compact receiver order[%d]=%d", i, receiver)
			}
		}
	}
	if len(witness.scalarCoins) < 2 || witness.scalarCoins[0][0].Equal(&witness.scalarCoins[1][0]) ||
		witness.blindingCoins[0].Equal(&witness.blindingCoins[1]) {
		t.Fatal("full compact dealer reused receiver encryption randomness")
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLeaf(wire, &leafContext)
	if err != nil {
		t.Fatalf("holder rejected full compact leaf: %v", err)
	}
	if err := cvVerifyLeaf(&leafContext, decoded); err != nil {
		t.Fatalf("full compact leaf verification failed: %v", err)
	}

	t.Run("ciphertext mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c, &genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&leafContext, bad); err == nil {
			t.Fatal("accepted full compact proof for a mutated ciphertext")
		}
	})
	t.Run("coefficient commitment mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.coefficientCommitments[0].Add(&bad.coefficientCommitments[0], &genG1)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&leafContext, bad); err == nil {
			t.Fatal("accepted full compact proof for a mutated coefficient commitment")
		}
	})
	t.Run("receiver order mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.compactProof.link.lanes[0], bad.compactProof.link.lanes[1] =
			bad.compactProof.link.lanes[1], bad.compactProof.link.lanes[0]
		if err := apvssVerifyCompactFallback(bad, bad.compactProof); err == nil {
			t.Fatal("accepted reordered full compact receiver proof")
		}
	})
	t.Run("missing receiver", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.compactProof.link.lanes = bad.compactProof.link.lanes[:len(bad.compactProof.link.lanes)-1]
		if err := apvssVerifyCompactFallback(bad, bad.compactProof); err == nil {
			t.Fatal("accepted full compact proof that omitted a receiver")
		}
	})
	t.Run("context mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.context.sessionID = []byte("other-full-compact-session")
		if err := apvssVerifyCompactFallback(bad, bad.compactProof); err == nil {
			t.Fatal("accepted full compact proof under another context")
		}
	})
	t.Run("fallback scope replay", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.context.proofProfile = cvLeafStructuralProofProfile
		if err := apvssVerifyCompactFallback(bad, bad.compactProof); err == nil {
			t.Fatal("full compact proof replayed into fallback scope")
		}
	})
	t.Run("comparator mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		one := fr.One()
		bad.compactProof.comparator.zRelation.Add(
			&bad.compactProof.comparator.zRelation, &one,
		)
		if err := apvssVerifyCompactFallback(bad, bad.compactProof); err == nil {
			t.Fatal("accepted mutated full compact comparator")
		}
	})
	t.Run("proof mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		one := fr.One()
		bad.compactProof.digitRange.tHat.Add(&bad.compactProof.digitRange.tHat, &one)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&leafContext, bad); err == nil {
			t.Fatal("accepted mutated full compact range proof")
		}
	})
}

func TestCVFullExactAndCompactPreserveScalarOutput(t *testing.T) {
	secret := cvTestScalar(101)
	key, err := cvReceiverPublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	baseContext := cvLeafContext{
		sessionID:                 []byte("full-backend-output-equivalence"),
		epoch:                     1,
		sharingDegree:             0,
		profile:                   cvChunkProfile{chunkBits: 8, maxComponents: 1},
		receiverPublicKeys:        []bls12381.G1Affine{key},
		receiverSigningPublicKeys: cvTestSigningKeys(t, 1, 24001),
		dealerSetPolicy:           []byte("first-f-plus-one"),
	}
	chunks, err := cvChunkCount(baseContext.profile)
	if err != nil {
		t.Fatal(err)
	}
	scalarCoefficients := []fr.Element{cvTestScalar(12345)}
	blindingCoefficients := []fr.Element{cvTestScalar(67890)}
	scalarCoins := [][]fr.Element{cvTestCoins(chunks, 1000)}
	blindingCoins := []fr.Element{cvTestScalar(2000)}

	exactContext := baseContext
	exactContext.proofProfile = cvLeafGrothProofProfile
	exactLeaf, err := cvReferenceDeal(
		exactContext, 7, scalarCoefficients, blindingCoefficients, scalarCoins, blindingCoins,
	)
	if err != nil {
		t.Fatal(err)
	}
	compactContext := baseContext
	compactContext.proofProfile = cvLeafFullCompactProofProfile
	compactLeaf, err := cvReferenceDeal(
		compactContext, 7, scalarCoefficients, blindingCoefficients, scalarCoins, blindingCoins,
	)
	if err != nil {
		t.Fatal(err)
	}
	exactAggregate, err := cvAgg(&exactContext, []*cvLeaf{exactLeaf})
	if err != nil {
		t.Fatal(err)
	}
	compactAggregate, err := cvAgg(&compactContext, []*cvLeaf{compactLeaf})
	if err != nil {
		t.Fatal(err)
	}
	exactShare, _, err := cvDecShare(exactAggregate, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	compactShare, _, err := cvDecShare(compactAggregate, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !exactShare.scalar.Equal(&compactShare.scalar) ||
		!exactShare.publicScalar.Equal(&compactShare.publicScalar) ||
		!exactShare.blindingOpening.Equal(&compactShare.blindingOpening) {
		t.Fatal("full proof backend changed scalar-output semantics")
	}
}

func TestACKFallbackDealerUsesIndependentReceiverCoins(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.APVSSMode = APVSSModeACKFallback
	dirs := generateCVReceiverKeysForTest(t, cfg.SID, cfg.NewCommittee)
	material, err := cvLoadReceiverKeyMaterial(
		dirs.public, dirs.secret, cfg.SID, cfg.NewCommittee, []int{cfg.NewCommittee[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		t.Fatal(err)
	}
	_, witness, err := cvRandomDealerLeafWithWitness(leafContext, cfg.LocalNodeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(witness.scalarCoins) < 2 || len(witness.scalarCoins[0]) == 0 {
		t.Fatal("missing per-receiver encryption coins")
	}
	if witness.scalarCoins[0][0].Equal(&witness.scalarCoins[1][0]) {
		t.Fatal("ACK/fallback dealer reused receiver scalar encryption randomness")
	}
	for i := range witness.blindingCoins {
		if !witness.blindingCoins[i].IsZero() {
			t.Fatalf("ACK/fallback receiver %d retained auxiliary blinding randomness", i+1)
		}
	}
}

func TestCVBuildEpochContextUsesNewCommitteeFaultThreshold(t *testing.T) {
	receiverIDs := []int{10, 11, 12, 13, 14, 15, 16}
	receiverKeys := make([]bls12381.G1Affine, len(receiverIDs))
	for i := range receiverKeys {
		key, err := cvReceiverPublicKey(cvTestScalar(uint64(i + 1)))
		if err != nil {
			t.Fatal(err)
		}
		receiverKeys[i] = key
	}
	cfg := NormalizeConfig(Config{
		SID:          "cv-asymmetric-thresholds",
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: receiverIDs,
		FOld:         1,
		FNew:         2,
	})
	leafContext, err := cvBuildEpochLeafContext(cfg, &cvReceiverKeyMaterial{
		receiverPublicKeys:        receiverKeys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(receiverKeys), 30001),
		registryDigest:            make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if leafContext.sharingDegree != 2 {
		t.Fatalf("APVSS sharing degree=%d, want f_n=2", leafContext.sharingDegree)
	}
	if leafContext.profile.maxComponents != 2 {
		t.Fatalf("aggregate component bound=%d, want f_o+1=2", leafContext.profile.maxComponents)
	}
}

func TestCVRunMaterializedAgreementRejectsMissingLocalRLO(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.LocalNodeIDs = []int{0}
	if _, _, err := cvRunMaterializedAgreement(context.Background(), cfg, nil); err == nil {
		t.Fatal("materialized agreement accepted a missing local RLO")
	}
}
