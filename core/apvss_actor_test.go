package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestAPVSSReceiverActorsCollectACKsV1(t *testing.T) {
	fixture := apvssFixture(t, 4, 1)
	fixture.leaf.dealerID = 0
	fixture.leaf.digest = cvLeafDigest(fixture.leaf)
	oldNodes := []int{0, 1, 2, 3}
	receiverOrder := []int{10, 11, 12, 13}
	allNodes := sortedUnique(append(append([]int(nil), oldNodes...), receiverOrder...))
	cfg := NormalizeConfig(Config{
		SID: string(fixture.context.sessionID), Epoch: int(fixture.context.epoch),
		OldCommittee: oldNodes, NewCommittee: receiverOrder, FOld: 1, FNew: 1, Kappa: 2,
		APVSSFallbackProfile:   apvssFallbackCompactBatchProfile,
		AllowExperimentalAPVSS: true, APVSSBenchmarkFallbackCount: 1,
		LocalNodeIDs: oldNodes, ArtifactCacheDir: t.TempDir(),
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(allNodes, 128)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		oldNodes, receiverOrder, allNodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	secrets := make(map[int]fr.Element, len(receiverOrder))
	signingSecrets := make(map[int]fr.Element, len(receiverOrder))
	for i, receiverID := range receiverOrder {
		secrets[receiverID] = fixture.receiverSecrets[i]
		signingSecrets[receiverID] = cvTestScalar(uint64(10001 + i))
		fixture.context.receiverSigningPublicKeys[i], err = cvReceiverPublicKey(signingSecrets[receiverID])
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.leaf.context = cvCloneLeafContext(fixture.context)
	fixture.leaf.digest = cvLeafDigest(fixture.leaf)
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentServiceWithReceivers(
		context.Background(), cfg, &fixture.context, 0, transport, router, store,
		receiverOrder, secrets, signingSecrets,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prototype, err := service.CollectAPVSSLaneACKs(ctx, fixture.leaf, &fixture.witness)
	if err != nil {
		t.Fatal(err)
	}
	fallbackCount := apvssPrototypeFallbackCount(prototype)
	if len(prototype.acks) != len(receiverOrder)-1 || fallbackCount != 1 {
		t.Fatalf("actor ACK/fallback counts = %d/%d", len(prototype.acks), fallbackCount)
	}
	if prototype.fallbackProfile != apvssFallbackCompactBatchProfile || prototype.compactFallback == nil {
		t.Fatal("actor did not assemble the experimental compact fallback profile")
	}
	if err := apvssVerifyPrototype(&fixture.context, prototype); err != nil {
		t.Fatalf("actor-produced APVSS leaf rejected: %v", err)
	}
	if transport.sentCount(apvssTagLaneOffer) != len(receiverOrder) ||
		transport.sentCount(apvssTagLaneACK) < len(receiverOrder)-fixture.context.sharingDegree {
		t.Fatal("receiver actors did not exchange the expected offer/ACK messages")
	}
}

func TestAPVSSReceiverActorsFeedAvailabilityAndVerifiedCacheV1(t *testing.T) {
	fixture := apvssFixture(t, 4, 1)
	fixture.leaf.dealerID = 0
	fixture.leaf.digest = cvLeafDigest(fixture.leaf)
	oldNodes := []int{0, 1, 2, 3}
	receiverOrder := []int{10, 11, 12, 13}
	allNodes := sortedUnique(append(append([]int(nil), oldNodes...), receiverOrder...))
	cfg := NormalizeConfig(Config{
		SID: string(fixture.context.sessionID), Epoch: int(fixture.context.epoch),
		OldCommittee: oldNodes, NewCommittee: receiverOrder, FOld: 1, FNew: 1, Kappa: 2,
		LocalNodeIDs: oldNodes, ArtifactCacheDir: t.TempDir(),
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(allNodes, 256)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		oldNodes, receiverOrder, allNodes, 128,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentService, len(oldNodes))
	signingSecrets := make([]fr.Element, len(receiverOrder))
	for i := range signingSecrets {
		signingSecrets[i] = cvTestScalar(uint64(11001 + i))
		fixture.context.receiverSigningPublicKeys[i], err = cvReceiverPublicKey(signingSecrets[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.leaf.context = cvCloneLeafContext(fixture.context)
	fixture.leaf.digest = cvLeafDigest(fixture.leaf)
	for i, node := range oldNodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentServiceWithReceivers(
			context.Background(), cfg, &fixture.context, node, transport, router, store,
			receiverOrder,
			map[int]fr.Element{receiverOrder[i]: fixture.receiverSecrets[i]},
			map[int]fr.Element{receiverOrder[i]: signingSecrets[i]},
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prototype, err := services[0].CollectAPVSSLaneACKs(ctx, fixture.leaf, &fixture.witness)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := services[0].DisperseAPVSS(ctx, prototype)
	if err != nil {
		t.Fatalf(
			"disperse APVSS: %v (init=%d component_ack=%d)",
			err,
			transport.sentCount(cvTagComponentInit),
			transport.sentCount(cvTagComponentAck),
		)
	}
	if !bytes.Equal(descriptor.leafDigest, prototype.digest) {
		t.Fatal("availability descriptor did not bind the APVSS leaf digest")
	}
	for _, service := range services {
		service.mu.Lock()
		cachedBefore := len(service.verifiedLeaves)
		service.mu.Unlock()
		if cachedBefore != 0 {
			t.Fatal("availability lock performed APVSS proof verification")
		}
		accepted, err := service.loadOrRetrieveComponent(ctx, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if accepted.apvss == nil || !bytes.Equal(accepted.leafDigest, prototype.digest) {
			t.Fatal("materializer did not cache an APVSS-verified leaf token")
		}
		if err := cvValidateAcceptedLeaf(&fixture.context, accepted); err != nil {
			t.Fatalf("cached APVSS token rejected: %v", err)
		}
	}
}
