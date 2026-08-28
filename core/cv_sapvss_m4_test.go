package core

import (
	"bytes"
	"math/big"
	"strings"
	"sync"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVSAPVSSM4MaterializeRecoverReceipt(t *testing.T) {
	cfg, leafContext, receiverSecrets, leaves := cvM4Fixture(t)
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.rlo.Header.Dealers) != cfg.FOld+1 {
		t.Fatalf("M4 dealer count mismatch: have=%d want=%d", len(materialized.rlo.Header.Dealers), cfg.FOld+1)
	}
	if len(materialized.rlo.Header.PayloadDigest) != 32 || len(materialized.rlo.Header.FreshShardRoot) != 32 {
		t.Fatal("M4 ARC header did not bind the aggregate payload and fresh shard root")
	}
	if !materialized.rlo.Lock.Ready() || materialized.rlo.Lock.Threshold != len(cfg.OldCommittee)-cfg.FOld {
		t.Fatal("M4 ARC did not use the n_o-f_o signer quorum")
	}

	agreedDigest := materialized.rlo.Digest
	if !bytes.Equal(agreedDigest, materialized.rlo.Digest) {
		t.Fatal("M4 agreement did not decide the materialized AggRLO digest")
	}

	recoveryThreshold := len(cfg.OldCommittee) - 2*cfg.FOld
	available := make([]int, recoveryThreshold)
	for i := range available {
		available[i] = i
	}
	recovered, err := cvRecoverMaterializedAggregate(cfg, materialized, agreedDigest, available)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, receipt, err := cvDecShare(recovered, receiverSecrets[0], 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyShare(&leafContext, recovered, 1, receipt); err != nil {
		t.Fatalf("M4 recovered receipt rejected: %v", err)
	}
	want := cvTestScalar(24) // (5+3*1) + (11+5*1).
	if !decrypted.scalar.Equal(&want) {
		t.Fatalf("M4 recovered scalar mismatch: have=%s want=%s", decrypted.scalar.String(), want.String())
	}
}

func TestCVSAPVSSRSEncoderCacheRespectsWorkerBudget(t *testing.T) {
	t.Setenv("RLADKR_RS_WORKERS", "1")
	one, err := cvCachedRSEncoder(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	again, err := cvCachedRSEncoder(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	if one != again {
		t.Fatal("identical RS dimensions did not reuse the cached encoder")
	}
	t.Setenv("RLADKR_RS_WORKERS", "2")
	differentBudget, err := cvCachedRSEncoder(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	if one == differentBudget {
		t.Fatal("RS encoder cache ignored the worker budget")
	}
}

func TestCVSAPVSSM4DeterministicFreshDispersalRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("M4 dispersal integration test")
	}
	_, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cvDisperseAggregate(agg, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cvDisperseAggregate(agg, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.nonce, second.nonce) || !bytes.Equal(first.root, second.root) {
		t.Fatal("honest materializers did not converge on the same aggregate dispersal")
	}
	differentAgg, err := cvAgg(&leafContext, leaves[:1])
	if err != nil {
		t.Fatal(err)
	}
	different, err := cvDisperseAggregate(differentAgg, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.nonce, different.nonce) || bytes.Equal(first.root, different.root) {
		t.Fatal("different aggregates reused deterministic fresh dispersal material")
	}
}

func TestCVSAPVSSThresholdOutputUsesLocalSharesAndPublicReceipts(t *testing.T) {
	_, leafContext, receiverSecrets, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	receiverOrder := []int{10, 11, 12, 13}
	localShares, receiptWires, err := cvCreateLocalDecryptionOutputs(
		&leafContext, agg, receiverOrder, map[int]fr.Element{
			10: receiverSecrets[0],
			11: receiverSecrets[1],
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(localShares) != 2 || len(localShares[10]) != fr.Bytes || len(receiptWires) != 2 {
		t.Fatal("local scalar outputs or public receipts are incomplete")
	}
	publicKey, err := cvThresholdPublicKeyFromReceipts(
		&leafContext, agg, receiverOrder, receiptWires,
	)
	if err != nil {
		t.Fatal(err)
	}
	var want bls12381.G1Affine
	wantScalar := cvTestScalar(16)
	want.ScalarMultiplication(&genG1, wantScalar.BigInt(new(big.Int)))
	encodedWant := want.Bytes()
	if !bytes.Equal(publicKey, encodedWant[:]) {
		t.Fatal("receipt interpolation produced the wrong scalar threshold public key")
	}

	bad := make(map[int][]byte, len(receiptWires))
	for receiver, wire := range receiptWires {
		bad[receiver] = append([]byte(nil), wire...)
	}
	bad[10][len(bad[10])-1] ^= 1
	if _, err := cvThresholdPublicKeyFromReceipts(&leafContext, agg, []int{10, 11}, bad); err == nil {
		t.Fatal("threshold-key derivation accepted a mutated public receipt")
	}
}

func TestCVSAPVSSPreparedReceiptsReuseVerifiedTokens(t *testing.T) {
	_, leafContext, receiverSecrets, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	receiverOrder := []int{10, 11, 12, 13}
	prepared, err := cvPrepareLocalDecryptionOutputs(
		&leafContext, agg, receiverOrder, map[int]fr.Element{
			10: receiverSecrets[0], 11: receiverSecrets[1],
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	fromTokens, err := cvThresholdPublicKeyFromVerifiedReceipts(
		&leafContext, agg, receiverOrder, prepared.verified,
	)
	if err != nil {
		t.Fatal(err)
	}
	fromWire, err := cvThresholdPublicKeyFromReceipts(
		&leafContext, agg, receiverOrder, prepared.receipts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromTokens, fromWire) {
		t.Fatal("verified receipt token interpolation differs from full wire verification")
	}

	prepared.verified[10].wire = append([]byte(nil), prepared.verified[10].wire...)
	prepared.verified[10].wire[len(prepared.verified[10].wire)-1] ^= 1
	if _, err := cvThresholdPublicKeyFromVerifiedReceipts(
		&leafContext, agg, receiverOrder, prepared.verified,
	); err == nil {
		t.Fatal("mutated cached receipt token was accepted")
	}
}

func TestCVSAPVSSM4FreshBuilderMatchesCheckedBuilder(t *testing.T) {
	if testing.Short() {
		t.Skip("M4 builder integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(agg, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := cvBuildMaterializedAggRLO(cfg, &leafContext, leaves, agg, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := cvBuildMaterializedAggRLOFromVerifiedAggregate(cfg, agg, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checked.rlo.Header.AggregateDigest, fresh.rlo.Header.AggregateDigest) ||
		!bytes.Equal(checked.rlo.Header.PayloadDigest, fresh.rlo.Header.PayloadDigest) ||
		!bytes.Equal(checked.rlo.Header.FreshShardRoot, fresh.rlo.Header.FreshShardRoot) {
		t.Fatal("fresh and checked builders produced different ARC bindings")
	}

	badLeaves := append([]*cvLeaf(nil), leaves...)
	badLeaf := *badLeaves[0]
	badLeaf.digest = append([]byte(nil), badLeaf.digest...)
	badLeaf.digest[0] ^= 1
	badLeaves[0] = &badLeaf
	if _, err := cvBuildMaterializedAggRLO(cfg, &leafContext, badLeaves, agg, dispersal); err == nil {
		t.Fatal("checked builder accepted a mutated leaf digest")
	}
}

func TestCVSAPVSSM4ARCRejectsUnmaterializedAggregate(t *testing.T) {
	if testing.Short() {
		t.Skip("M4 ARC integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvBuildMaterializedAggRLO(cfg, &leafContext, leaves, agg, nil); err == nil {
		t.Fatal("ARC signed a CV-sAPVSS aggregate without materialized shards")
	}
}

func TestCVSAPVSSM4ARCRejectsWrongErasureDimensions(t *testing.T) {
	if testing.Short() {
		t.Skip("M4 ARC integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	badDispersal, err := cvDisperseAggregate(agg, len(cfg.OldCommittee), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvBuildMaterializedAggRLO(cfg, &leafContext, leaves, agg, badDispersal); err == nil {
		t.Fatal("ARC accepted aggregate shards with recovery threshold below n_o-2f_o")
	}
}

func TestCVSAPVSSM4RejectsInvalidErasureCodeword(t *testing.T) {
	_, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(agg, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	bad := *dispersal
	bad.nonce = append([]byte(nil), dispersal.nonce...)
	bad.payloadDigest = append([]byte(nil), dispersal.payloadDigest...)
	bad.root = append([]byte(nil), dispersal.root...)
	bad.shards = make([]cvAggregateShard, len(dispersal.shards))
	payloads := make([][]byte, len(bad.shards))
	for i := range bad.shards {
		bad.shards[i] = dispersal.shards[i]
		bad.shards[i].payload = append([]byte(nil), dispersal.shards[i].payload...)
		bad.shards[i].siblings = make([][]byte, len(dispersal.shards[i].siblings))
		for j := range bad.shards[i].siblings {
			bad.shards[i].siblings[j] = append([]byte(nil), dispersal.shards[i].siblings[j]...)
		}
		payloads[i] = bad.shards[i].payload
	}
	bad.shards[bad.dataShards].payload[0] ^= 1
	root, branches := cvBuildAggregateMerkle(dispersal.nonce, payloads)
	bad.root = root
	for i := range bad.shards {
		bad.shards[i].siblings = branches[i]
	}

	err = cvVerifyAggregateDispersal(agg, &bad)
	if err == nil || !strings.Contains(err.Error(), "codeword") {
		t.Fatalf("invalid erasure codeword was not rejected: %v", err)
	}
}

func TestCVSAPVSSM4FromVerifiedRejectsAggregateDigestMutation(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(agg, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	bad := *agg
	bad.digest = append([]byte(nil), agg.digest...)
	bad.digest[0] ^= 1

	_, err = cvBuildMaterializedAggRLOFromVerifiedAggregate(cfg, &bad, dispersal)
	if err == nil || !strings.Contains(err.Error(), "wire or digest mismatch") {
		t.Fatalf("FromVerified accepted a mutated aggregate digest: %v", err)
	}
}

func TestCVSAPVSSM4RecoverRejectsRootAndShardMutation(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("signed fresh root", func(t *testing.T) {
		bad := *materialized
		bad.rlo = cloneAggRLO(materialized.rlo)
		bad.rlo.Header.FreshShardRoot[0] ^= 1
		bad.rlo.Digest = digestAggRLO(*bad.rlo)
		if _, err := cvRecoverMaterializedAggregate(cfg, &bad, bad.rlo.Digest, []int{0, 1}); err == nil {
			t.Fatal("recovered after mutating the ARC-bound fresh shard root")
		}
	})

	t.Run("available shard payload", func(t *testing.T) {
		bad := cvCloneMaterializedAggregateForTest(materialized)
		bad.dispersal.shards[0].payload[0] ^= 1
		if _, err := cvRecoverMaterializedAggregate(cfg, bad, bad.rlo.Digest, []int{0, 1}); err == nil {
			t.Fatal("recovered after mutating an available aggregate shard")
		}
	})

	t.Run("erasure dimensions", func(t *testing.T) {
		bad := cvCloneMaterializedAggregateForTest(materialized)
		bad.dispersal.dataShards++
		if _, err := cvRecoverMaterializedAggregate(cfg, bad, bad.rlo.Digest, []int{0, 1, 2}); err == nil {
			t.Fatal("recovered after mutating the ARC-required erasure dimensions")
		}
	})
}

func TestCVSAPVSSM4RecoverRejectsUnagreedLocalAggregate(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	agreedDigest := append([]byte(nil), materialized.rlo.Digest...)
	agreedDigest[0] ^= 1
	if _, err := cvRecoverMaterializedAggregate(cfg, materialized, agreedDigest, []int{0, 1}); err == nil {
		t.Fatal("recovered a local aggregate that was not selected by MVBA")
	}
}

func TestCVSAPVSSM4RejectsDealerOutsideOldCommittee(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	cfg.OldCommittee = []int{2, 3, 4, 5}
	if _, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves); err == nil || !strings.Contains(err.Error(), "outside old committee") {
		t.Fatalf("M4 did not reject leaves from dealers outside the old committee: %v", err)
	}
}

func TestCVSAPVSSM4RejectsDealerIDOutsideIntRange(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	badLeaves := append([]*cvLeaf(nil), leaves...)
	badLeaf := *badLeaves[1]
	badLeaf.dealerID = uint64(^uint(0)>>1) + 1
	badLeaves[1] = &badLeaf
	if _, err := cvMaterializeAndLockAggregate(cfg, &leafContext, badLeaves); err == nil || !strings.Contains(err.Error(), "dealer ID exceeds int") {
		t.Fatalf("M4 did not reject a dealer ID outside the local int range before aggregation: %v", err)
	}
}

func TestCVSAPVSSM4DecodeRejectsOversizedReceiverCountBeforeAllocation(t *testing.T) {
	const receiverCount = 1 << 16
	base, _, chunks, err := cvProfile(cvChunkProfile{chunkBits: 4, maxComponents: 2})
	if err != nil {
		t.Fatal(err)
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	for _, value := range [][]byte{
		[]byte("ARL-CV-sAPVSS"), []byte(cvLeafGroupID), fr.Modulus().Bytes(),
	} {
		if err := cvWriteBytes(&wire, value); err != nil {
			t.Fatal(err)
		}
	}
	cvWritePoint(&wire, &genG1)
	cvWritePoint(&wire, &h)
	if err := cvWriteBytes(&wire, []byte("oversized-context")); err != nil {
		t.Fatal(err)
	}
	cvWriteUint64(&wire, 1)
	if err := cvWriteBytes(&wire, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []int{receiverCount, 1, 2, 4, int(base), chunks} {
		if err := cvWriteUint32(&wire, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := cvWriteBytes(&wire, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := cvWriteUint32(&wire, receiverCount); err != nil {
		t.Fatal(err)
	}

	_, err = cvDecodeLeafContext(wire.Bytes())
	if err == nil || !strings.Contains(err.Error(), "receiver count exceeds remaining wire") {
		t.Fatalf("oversized receiver count was not rejected before allocation: %v", err)
	}
}

func TestCVSAPVSSM4DecodeAggregateRejectsReceiverCountBeyondRemainingWire(t *testing.T) {
	context, _, leaves := cvM2Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		t.Fatal(err)
	}
	r := newCVWireReader(wire)
	if _, err := r.bytes(256); err != nil {
		t.Fatal(err)
	}
	if _, err := r.bytes(cvMaxCanonicalFieldBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := r.bytes(32); err != nil {
		t.Fatal(err)
	}
	dealerCount, err := r.uint32()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < dealerCount; i++ {
		if _, err := r.uint64(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.bytes(32); err != nil {
			t.Fatal(err)
		}
	}
	commitmentCount, err := r.uint32()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < commitmentCount; i++ {
		if _, err := r.point(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.uint32(); err != nil {
		t.Fatal(err)
	}
	wire = wire[:len(wire)-r.reader.Len()]

	_, err = cvDecodeAggregate(wire)
	if err == nil || !strings.Contains(err.Error(), "CV-sAPVSS aggregate receiver count exceeds remaining wire") {
		t.Fatalf("aggregate receiver count was not rejected before allocation: %v", err)
	}
}

func TestCVSAPVSSM4DecodeAggregateRejectsDealerCountBeyondRemainingWire(t *testing.T) {
	key, err := cvReceiverPublicKey(cvTestScalar(13))
	if err != nil {
		t.Fatal(err)
	}
	context := cvLeafContext{
		sessionID:                 []byte("dealer-count-bound"),
		epoch:                     1,
		sharingDegree:             0,
		profile:                   cvChunkProfile{chunkBits: 1, maxComponents: 1 << 20},
		receiverPublicKeys:        []bls12381.G1Affine{key},
		receiverSigningPublicKeys: cvTestSigningKeys(t, 1, 25001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafStructuralProofProfile,
	}
	contextWire, err := cvLeafContextCanonicalBytes(&context)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	for _, value := range [][]byte{
		[]byte(cvAggregateDomain), contextWire, cvLeafContextDigest(&context),
	} {
		if err := cvWriteBytes(&wire, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := cvWriteUint32(&wire, 1<<20); err != nil {
		t.Fatal(err)
	}

	_, err = cvDecodeAggregate(wire.Bytes())
	if err == nil || !strings.Contains(err.Error(), "aggregate dealer count exceeds remaining wire") {
		t.Fatalf("oversized aggregate dealer count was not rejected before allocation: %v", err)
	}
}

func TestCVSAPVSSM4DecodeAggregateRejectsCommitmentCountBeyondRemainingWire(t *testing.T) {
	context, _, leaves := cvM2Fixture(t)
	contextWire, err := cvLeafContextCanonicalBytes(&context)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	for _, value := range [][]byte{
		[]byte(cvAggregateDomain), contextWire, cvLeafContextDigest(&context),
	} {
		if err := cvWriteBytes(&wire, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := cvWriteUint32(&wire, 1); err != nil {
		t.Fatal(err)
	}
	cvWriteUint64(&wire, leaves[0].dealerID)
	if err := cvWriteBytes(&wire, leaves[0].digest); err != nil {
		t.Fatal(err)
	}
	if err := cvWriteUint32(&wire, context.sharingDegree+1); err != nil {
		t.Fatal(err)
	}

	_, err = cvDecodeAggregate(wire.Bytes())
	if err == nil || !strings.Contains(err.Error(), "aggregate commitment count exceeds remaining wire") {
		t.Fatalf("aggregate commitment count was not rejected before allocation: %v", err)
	}
}

var (
	cvM4FixtureOnce            sync.Once
	cvM4FixtureContext         cvLeafContext
	cvM4FixtureReceiverSecrets []fr.Element
	cvM4FixtureLeaves          []*cvLeaf
)

func cvBuildSharedM4Fixture(t testing.TB) {
	t.Helper()
	receiverSecrets := []fr.Element{
		cvTestScalar(13),
		cvTestScalar(17),
		cvTestScalar(19),
		cvTestScalar(23),
	}
	receiverKeys := make([]bls12381.G1Affine, len(receiverSecrets))
	for i := range receiverSecrets {
		var err error
		receiverKeys[i], err = cvReceiverPublicKey(receiverSecrets[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	const sid = "cv-m4-shared-fixture-v1"
	leafContext := cvLeafContext{
		sessionID:                 []byte(sid),
		epoch:                     1,
		sharingDegree:             1,
		profile:                   cvChunkProfile{chunkBits: 4, maxComponents: 2},
		receiverPublicKeys:        receiverKeys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(receiverKeys), 26001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	chunks, err := cvChunkCount(leafContext.profile)
	if err != nil {
		t.Fatal(err)
	}
	deal := func(dealer uint64, scalar, blinding []fr.Element, coinStart uint64) *cvLeaf {
		commonCoins := cvTestCoins(chunks, coinStart)
		scalarCoins := make([][]fr.Element, len(receiverKeys))
		blindingCoins := make([]fr.Element, len(receiverKeys))
		for i := range receiverKeys {
			scalarCoins[i] = append([]fr.Element(nil), commonCoins...)
			blindingCoins[i] = cvTestScalar(coinStart + uint64(chunks) + 1)
		}
		leaf, dealErr := cvReferenceDeal(
			leafContext, dealer, scalar, blinding, scalarCoins, blindingCoins,
		)
		if dealErr != nil {
			t.Fatal(dealErr)
		}
		return leaf
	}
	leaves := []*cvLeaf{
		deal(0, []fr.Element{cvTestScalar(5), cvTestScalar(3)}, []fr.Element{cvTestScalar(7), cvTestScalar(2)}, 100),
		deal(1, []fr.Element{cvTestScalar(11), cvTestScalar(5)}, []fr.Element{cvTestScalar(13), cvTestScalar(4)}, 300),
	}
	cvM4FixtureContext = cvCloneLeafContext(leafContext)
	cvM4FixtureReceiverSecrets = append([]fr.Element(nil), receiverSecrets...)
	cvM4FixtureLeaves = leaves
}

func cvCloneM4LeafForTest(leaf *cvLeaf) *cvLeaf {
	if leaf == nil {
		return nil
	}
	cloned := *leaf
	cloned.context = cvCloneLeafContext(leaf.context)
	cloned.coefficientCommitments = append([]bls12381.G1Affine(nil), leaf.coefficientCommitments...)
	cloned.receivers = make([]cvLeafReceiver, len(leaf.receivers))
	for i := range leaf.receivers {
		cloned.receivers[i] = leaf.receivers[i]
		if leaf.receivers[i].encryptedShare != nil {
			encrypted := *leaf.receivers[i].encryptedShare
			encrypted.scalarChunks = append([]cvElGamalCiphertext(nil), encrypted.scalarChunks...)
			cloned.receivers[i].encryptedShare = &encrypted
		}
	}
	if leaf.proof != nil {
		proof := *leaf.proof
		proof.chunking.b = append([]bls12381.G1Affine(nil), leaf.proof.chunking.b...)
		proof.chunking.c = append([]bls12381.G1Affine(nil), leaf.proof.chunking.c...)
		proof.chunking.d = append([]bls12381.G1Affine(nil), leaf.proof.chunking.d...)
		proof.chunking.zCoins = append([]fr.Element(nil), leaf.proof.chunking.zCoins...)
		proof.chunking.zDigits = append([]fr.Element(nil), leaf.proof.chunking.zDigits...)
		proof.chunking.exactRange.commitments = append(
			[]bls12381.G1Affine(nil), leaf.proof.chunking.exactRange.commitments...,
		)
		proof.chunking.exactRange.bits = append(
			[]cvBitProof(nil), leaf.proof.chunking.exactRange.bits...,
		)
		proof.chunking.exactRange.links = make(
			[]cvRangeLinkProof, len(leaf.proof.chunking.exactRange.links),
		)
		for i := range leaf.proof.chunking.exactRange.links {
			proof.chunking.exactRange.links[i] = leaf.proof.chunking.exactRange.links[i]
			proof.chunking.exactRange.links[i].tCommitments = append(
				[]bls12381.G1Affine(nil), leaf.proof.chunking.exactRange.links[i].tCommitments...,
			)
			proof.chunking.exactRange.links[i].tCiphertexts = append(
				[]bls12381.G1Affine(nil), leaf.proof.chunking.exactRange.links[i].tCiphertexts...,
			)
			proof.chunking.exactRange.links[i].zDigits = append(
				[]fr.Element(nil), leaf.proof.chunking.exactRange.links[i].zDigits...,
			)
			proof.chunking.exactRange.links[i].zRhos = append(
				[]fr.Element(nil), leaf.proof.chunking.exactRange.links[i].zRhos...,
			)
		}
		cloned.proof = &proof
	}
	cloned.digest = append([]byte(nil), leaf.digest...)
	return &cloned
}

func cvM4Fixture(t testing.TB) (Config, cvLeafContext, []fr.Element, []*cvLeaf) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping exact-range CV M4 fixture in short mode")
	}
	cvM4FixtureOnce.Do(func() { cvBuildSharedM4Fixture(t) })
	leafContext := cvCloneLeafContext(cvM4FixtureContext)
	receiverSecrets := append([]fr.Element(nil), cvM4FixtureReceiverSecrets...)
	leaves := make([]*cvLeaf, len(cvM4FixtureLeaves))
	for i := range cvM4FixtureLeaves {
		leaves[i] = cvCloneM4LeafForTest(cvM4FixtureLeaves[i])
	}
	cfg := NormalizeConfig(Config{
		SID:                string(leafContext.sessionID),
		Epoch:              1,
		OldCommittee:       []int{0, 1, 2, 3},
		NewCommittee:       []int{0, 1, 2, 3},
		FOld:               1,
		FNew:               1,
		Kappa:              2,
		AgreementTransport: "tcp-loopback",
		AgreementBindHost:  "127.0.0.1",
		ArtifactCacheDir:   t.TempDir(),
	})
	return cfg, leafContext, receiverSecrets, leaves
}

func cvCloneMaterializedAggregateForTest(in *cvMaterializedAggregate) *cvMaterializedAggregate {
	out := *in
	out.rlo = cloneAggRLO(in.rlo)
	copyDispersal := *in.dispersal
	copyDispersal.nonce = append([]byte(nil), in.dispersal.nonce...)
	copyDispersal.payloadDigest = append([]byte(nil), in.dispersal.payloadDigest...)
	copyDispersal.root = append([]byte(nil), in.dispersal.root...)
	copyDispersal.shards = make([]cvAggregateShard, len(in.dispersal.shards))
	for i := range copyDispersal.shards {
		copyDispersal.shards[i] = in.dispersal.shards[i]
		copyDispersal.shards[i].payload = append([]byte(nil), in.dispersal.shards[i].payload...)
		copyDispersal.shards[i].siblings = make([][]byte, len(in.dispersal.shards[i].siblings))
		for j := range copyDispersal.shards[i].siblings {
			copyDispersal.shards[i].siblings[j] = append([]byte(nil), in.dispersal.shards[i].siblings[j]...)
		}
	}
	out.dispersal = &copyDispersal
	return &out
}
