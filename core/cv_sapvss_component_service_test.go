package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCVComponentServiceDispersesCertifiesAndRetrievesOverNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("component network integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
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
		services[i], err = newCVComponentService(
			context.Background(), cfg, &leafContext, node, transport, router, store,
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

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	descriptor, err := services[0].Disperse(ctx, leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := transport.sentCount(cvTagComponentInit); got != len(nodes)-1 {
		t.Fatalf("component dispersal sent %d INIT messages, want %d without self-INIT", got, len(nodes)-1)
	}
	if len(descriptor.certificate) == 0 {
		t.Fatalf("component certificate is empty: %+v", descriptor)
	}
	if err := cvValidateComponentDescriptor(cfg, descriptor); err != nil {
		t.Fatalf("network-produced descriptor rejected: %v", err)
	}
	for _, service := range services {
		service.mu.Lock()
		cached := len(service.verifiedLeaves)
		service.mu.Unlock()
		if cached != 0 {
			t.Fatalf("availability lock populated node %d verified-leaf cache", service.localNode)
		}
	}

	getBefore := transport.sentCount(cvTagComponentGet)
	leafBefore := transport.sentCount(cvTagComponentLeaf)
	type retrieveResult struct {
		leaf *cvLeaf
		err  error
	}
	startRetrieval := make(chan struct{})
	retrievals := make(chan retrieveResult, 2)
	for range 2 {
		go func() {
			<-startRetrieval
			leaf, retrieveErr := services[len(services)-1].Retrieve(ctx, descriptor)
			retrievals <- retrieveResult{leaf: leaf, err: retrieveErr}
		}()
	}
	close(startRetrieval)
	var retrieved *cvLeaf
	for range 2 {
		result := <-retrievals
		if result.err != nil {
			t.Fatal(result.err)
		}
		if retrieved == nil {
			retrieved = result.leaf
		} else if retrieved != result.leaf {
			t.Fatal("component retrieval singleflight returned different verified objects")
		}
	}
	if !bytes.Equal(retrieved.digest, leaves[0].digest) ||
		transport.sentCount(cvTagComponentGet)-getBefore != len(nodes) ||
		transport.sentCount(cvTagComponentLeaf) <= leafBefore {
		t.Fatal("component retrieval did not singleflight one authenticated GET/LEAF round")
	}

	_, err = services[1].Disperse(ctx, leaves[1])
	if err != nil {
		t.Fatal(err)
	}
	insufficientCtx, insufficientCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if _, collectErr := services[0].CollectLocalComponentSet(insufficientCtx); collectErr == nil {
		insufficientCancel()
		t.Fatal("component candidate collection succeeded below n-f certified descriptors")
	}
	insufficientCancel()
	thirdLeaf, err := cvRandomDealerLeaf(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services[2].Disperse(ctx, thirdLeaf); err != nil {
		t.Fatal(err)
	}
	candidateSets := make(map[int][]*cvComponentDescriptor, len(services))
	for _, service := range services {
		candidates, collectErr := service.CollectLocalComponentSet(ctx)
		if collectErr != nil {
			t.Fatal(collectErr)
		}
		if len(candidates) != len(nodes)-cfg.FOld ||
			candidates[0].dealer != 0 || candidates[1].dealer != 1 || candidates[2].dealer != 2 {
			t.Fatalf("node %d collected unexpected component candidates: %+v", service.localNode, candidates)
		}
		candidateSets[service.localNode] = candidates
	}
	if got, wantAtLeast := transport.sentCount(cvTagComponentReady), len(nodes)*(len(nodes)-1); got < wantAtLeast {
		t.Fatalf("ReadyCert dissemination sent %d messages, want at least %d", got, wantAtLeast)
	}
	for _, service := range services {
		service.mu.Lock()
		published := len(service.publishedReadyRoots)
		accepted := len(service.acceptedReadyRoots)
		service.mu.Unlock()
		if published == 0 || accepted == 0 {
			t.Fatalf("node %d did not publish/accept a ReadyCert", service.localNode)
		}
	}
	type materializeResult struct {
		value *cvMaterializedAggregate
		err   error
	}
	materializedResults := make(chan materializeResult, len(services))
	for _, service := range services {
		service := service
		go func() {
			value, materializeErr := service.MaterializeFirstCertified(
				ctx, candidateSets[service.localNode],
			)
			materializedResults <- materializeResult{value: value, err: materializeErr}
		}()
	}
	var materialized *cvMaterializedAggregate
	for range services {
		result := <-materializedResults
		if result.err != nil {
			t.Fatal(result.err)
		}
		if materialized == nil {
			materialized = result.value
			continue
		}
		if !bytes.Equal(
			digestAggHeaderForLock(result.value.rlo.Header),
			digestAggHeaderForLock(materialized.rlo.Header),
		) || !bytes.Equal(result.value.aggregate.digest, materialized.aggregate.digest) {
			t.Fatal("concurrent materializers produced different aggregate headers")
		}
	}
	if got, want := transport.sentCount(cvTagAggregateManifest), len(nodes)-1; got != want {
		t.Fatalf("optimistic primary sent %d aggregate offers, want %d", got, want)
	}
	if materialized.rlo.Lock.Threshold != len(nodes)-cfg.FOld || len(materialized.rlo.Lock.Certificate) == 0 {
		t.Fatal("network ARC did not produce a compact recovered certificate")
	}
	for _, service := range services {
		service.mu.Lock()
		cachedOffers := len(service.verifiedAggregates)
		cachedDispersals := len(service.verifiedDispersals)
		cachedLeaves := len(service.verifiedLeaves)
		persistedFresh := len(service.persistedFreshArtifacts)
		service.mu.Unlock()
		if cachedLeaves != cfg.FOld+1 {
			t.Fatalf("node %d verified %d leaves, want K=%d", service.localNode, cachedLeaves, cfg.FOld+1)
		}
		if cachedOffers != 1 {
			t.Fatalf("node %d cached %d verified aggregate offers, want one", service.localNode, cachedOffers)
		}
		if cachedDispersals != 1 {
			t.Fatalf("node %d cached %d aggregate dispersals, want one", service.localNode, cachedDispersals)
		}
		if persistedFresh != 1 {
			t.Fatalf("node %d persisted %d fresh artifacts, want one per header", service.localNode, persistedFresh)
		}
	}
	stoppedHolder := services[0].localNode
	if err := services[stoppedHolder].Close(); err != nil {
		t.Fatal(err)
	}
	recoverGetBefore := transport.sentCount(cvTagRecoverGet)
	recoverShardBefore := transport.sentCount(cvTagRecoverShard)
	recovered, err := services[len(services)-1].RecoverAggregate(ctx, materialized.rlo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.digest, materialized.aggregate.digest) ||
		transport.sentCount(cvTagRecoverGet) <= recoverGetBefore ||
		transport.sentCount(cvTagRecoverShard)-recoverShardBefore < len(nodes)-2*cfg.FOld {
		t.Fatal("aggregate recovery did not collect n-2f ARC-holder shards over the network")
	}
}

func TestCVAggregateDispersalCacheReusesIdenticalAggregate(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	accepted := make([]*cvVerifiedLeaf, cfg.FOld+1)
	descriptors := make([]*cvComponentDescriptor, cfg.FOld+1)
	for i := range accepted {
		wire, err := cvLeafCanonicalBytes(leaves[i])
		if err != nil {
			t.Fatal(err)
		}
		accepted[i], err = cvAcceptedLeaf(&leafContext, leaves[i], wire)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptor{
			dealer: int(leaves[i].dealerID), leafDigest: accepted[i].leafDigest, certificate: []byte{1},
		}
	}
	aggregate, err := cvAggVerified(&leafContext, accepted)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(aggregate, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	header, err := cvBuildNetworkAggHeader(cfg, aggregate, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	manifestRoot, err := cvComponentManifestRoot(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	headerKey := fmt.Sprintf("%x", digestAggHeaderForLock(header))
	service := &cvComponentService{
		cfg: cfg, leafCtx: &leafContext,
		verifiedAggregates:       make(map[string]*cvAggregateTranscript),
		verifiedAggregatesByRoot: make(map[string]*cvAggregateTranscript),
		verifiedDispersals:       make(map[string]*cvAggregateDispersal),
	}
	service.verifiedAggregates[headerKey] = aggregate
	offer := &cvAggregateManifestOffer{header: header, descriptors: descriptors, root: manifestRoot}

	_, first, err := service.verifyAggregateManifestForARC(offer)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := service.verifyAggregateManifestForARC(offer)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(service.verifiedDispersals) != 1 {
		t.Fatal("identical aggregate offer did not reuse its verified RS dispersal")
	}
}

func TestCVARCCertificateWakesPendingCollectorAndRejectsMutation(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x41}, 32)
	threshold := len(cfg.OldCommittee) - cfg.FOld
	shares := make(map[int][]byte, threshold)
	for _, holder := range sortedUnique(cfg.OldCommittee)[:threshold] {
		share, err := cfg.runtime.lockSigner.SignShare(holder, "RL_AGG_LOCK", digest)
		if err != nil {
			t.Fatal(err)
		}
		shares[holder] = share
	}
	certificate, err := cfg.runtime.lockSigner.Recover("RL_AGG_LOCK", digest, shares)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvARCCertificateCanonicalBytes(digest, certificate)
	if err != nil {
		t.Fatal(err)
	}
	pending := &cvPendingARCShare{values: make(chan cvARCShare, 1), certificates: make(chan []byte, 1)}
	key := fmt.Sprintf("%x", digest)
	service := &cvComponentService{
		cfg: cfg, pendingARCs: map[string]*cvPendingARCShare{key: pending},
		aggregateCertificates: make(map[string][]byte),
	}
	service.handleARCCertificate(Message{From: cfg.OldCommittee[0], Body: wire})
	select {
	case got := <-pending.certificates:
		if !bytes.Equal(got, certificate) || !bytes.Equal(service.aggregateCertificates[key], certificate) {
			t.Fatal("valid recovered ARC certificate was not cached and delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("valid recovered ARC certificate did not wake the pending collector")
	}

	badDigest := bytes.Repeat([]byte{0x42}, 32)
	badKey := fmt.Sprintf("%x", badDigest)
	badPending := &cvPendingARCShare{values: make(chan cvARCShare, 1), certificates: make(chan []byte, 1)}
	service.pendingARCs[badKey] = badPending
	badCertificate := append([]byte(nil), certificate...)
	badCertificate[len(badCertificate)-1] ^= 1
	badWire, err := cvARCCertificateCanonicalBytes(badDigest, badCertificate)
	if err != nil {
		t.Fatal(err)
	}
	service.handleARCCertificate(Message{From: cfg.OldCommittee[0], Body: badWire})
	select {
	case <-badPending.certificates:
		t.Fatal("mutated ARC certificate woke a pending collector")
	case <-time.After(25 * time.Millisecond):
	}
	if service.aggregateCertificates[badKey] != nil {
		t.Fatal("mutated ARC certificate entered the verified cache")
	}
}

func TestCVCertifiedAggregatePublishesInEitherArrivalOrder(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves[:cfg.FOld+1])
	if err != nil {
		t.Fatal(err)
	}
	headerDigest := digestAggHeaderForLock(materialized.rlo.Header)
	certificateWire, err := cvARCCertificateCanonicalBytes(headerDigest, materialized.rlo.Lock.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	newService := func() (*cvComponentService, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		return &cvComponentService{
			ctx: ctx, cfg: cfg,
			aggregateCertificates:        make(map[string][]byte),
			verifiedAggregateCandidates:  make(map[string]*cvVerifiedAggregateCandidate),
			publishedCertifiedCandidates: make(map[string]struct{}),
			certifiedCandidates:          make(chan *cvMaterializedAggregate, 1),
		}, cancel
	}
	assertPublished := func(t *testing.T, service *cvComponentService) {
		t.Helper()
		select {
		case got := <-service.certifiedCandidates:
			if !bytes.Equal(got.rlo.Digest, materialized.rlo.Digest) ||
				!bytes.Equal(got.aggregate.digest, materialized.aggregate.digest) {
				t.Fatal("published certified aggregate changed its AggRLO binding")
			}
		case <-time.After(time.Second):
			t.Fatal("certified aggregate was not published")
		}
	}

	t.Run("candidate before certificate", func(t *testing.T) {
		service, cancel := newService()
		defer cancel()
		if err := service.rememberVerifiedAggregateCandidate(
			materialized.rlo.Header, materialized.aggregate, materialized.dispersal,
		); err != nil {
			t.Fatal(err)
		}
		service.handleARCCertificate(Message{From: cfg.OldCommittee[0], Body: certificateWire})
		assertPublished(t, service)
	})

	t.Run("certificate before candidate", func(t *testing.T) {
		service, cancel := newService()
		defer cancel()
		service.handleARCCertificate(Message{From: cfg.OldCommittee[0], Body: certificateWire})
		if err := service.rememberVerifiedAggregateCandidate(
			materialized.rlo.Header, materialized.aggregate, materialized.dispersal,
		); err != nil {
			t.Fatal(err)
		}
		assertPublished(t, service)
	})
}

func TestCVAggregateManifestOfferRejectsMutation(t *testing.T) {
	cfg, context, _, leaves := cvM4Fixture(t)
	accepted := make([]*cvVerifiedLeaf, cfg.FOld+1)
	descriptors := make([]*cvComponentDescriptor, cfg.FOld+1)
	for i := range accepted {
		wire, err := cvLeafCanonicalBytes(leaves[i])
		if err != nil {
			t.Fatal(err)
		}
		accepted[i], err = cvAcceptedLeaf(&context, leaves[i], wire)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptor{dealer: int(leaves[i].dealerID), leafDigest: accepted[i].leafDigest, certificate: []byte{4}}
	}
	aggregate, err := cvAggVerified(&context, accepted)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(aggregate, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	header, err := cvBuildNetworkAggHeader(cfg, aggregate, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cvComponentManifestRoot(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	readyRoot := bytes.Repeat([]byte{0x52}, 32)
	wire, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
		header: header, descriptors: descriptors, readyRoot: readyRoot, root: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateManifestOffer(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.readyRoot, readyRoot) || !bytes.Equal(decoded.root, root) || len(decoded.descriptors) != 0 {
		t.Fatal("manifest offer did not preserve its compact reference")
	}

	t.Run("manifest root mismatch", func(t *testing.T) {
		badDescriptors := append([]*cvComponentDescriptor(nil), descriptors...)
		copyDescriptor := *descriptors[0]
		copyDescriptor.leafDigest = append([]byte(nil), descriptors[0].leafDigest...)
		copyDescriptor.leafDigest[0] ^= 1
		badDescriptors[0] = &copyDescriptor
		if _, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
			header: header, descriptors: badDescriptors, readyRoot: readyRoot, root: root,
		}); err == nil {
			t.Fatal("encoded an aggregate manifest with a mismatched root")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeAggregateManifestOffer(append(wire, 0), cfg); err == nil {
			t.Fatal("accepted an aggregate manifest with trailing bytes")
		}
	})
	t.Run("unknown ReadyCert root is deferred", func(t *testing.T) {
		service := &cvComponentService{
			cfg:                    cfg,
			acceptedReadyRoots:     make(map[string]struct{}),
			pendingReadyOffers:     make(map[string][]Message),
			processingOffers:       make(map[string]struct{}),
			readyDescriptorsByRoot: make(map[string][]*cvComponentDescriptor),
		}
		service.handleAggregateOffer(Message{From: 1, Body: wire})
		key := fmt.Sprintf("%x", readyRoot)
		deadline := time.Now().Add(time.Second)
		for {
			service.mu.Lock()
			pending := len(service.pendingReadyOffers[key])
			service.mu.Unlock()
			if pending == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("aggregate offer with an unknown ReadyCert root was not deferred")
			}
			time.Sleep(time.Millisecond)
		}
		newReadyRoot := bytes.Repeat([]byte{0x53}, 32)
		newWire, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
			header: header, descriptors: descriptors, readyRoot: newReadyRoot, root: root,
		})
		if err != nil {
			t.Fatal(err)
		}
		service.handleAggregateOffer(Message{From: 1, Body: newWire})
		newKey := fmt.Sprintf("%x", newReadyRoot)
		deadline = time.Now().Add(time.Second)
		for {
			service.mu.Lock()
			oldPending := len(service.pendingReadyOffers[key])
			newPending := len(service.pendingReadyOffers[newKey])
			service.mu.Unlock()
			if oldPending == 0 && newPending == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("unknown-root pending offers were not bounded to one per sender")
			}
			time.Sleep(time.Millisecond)
		}
	})
}

func TestCVAggregateManifestOfferExactRetryUsesCachedARCWire(t *testing.T) {
	cfg := NormalizeConfig(Config{SID: "arc-retry-cache", Epoch: 7})
	transport := newCVRouterTestTransport([]int{1}, 2)
	offer := &cvAggregateManifestOffer{}
	msg := Message{From: 1, Body: []byte("canonical-offer")}
	responseKey := fmt.Sprintf("%d:%x", msg.From, hashBytes(msg.Body))
	want := []byte("cached-arc-share")
	service := &cvComponentService{
		cfg: cfg, localNode: 0, transport: transport, processingOffers: make(map[string]struct{}),
		localARCShareWires: map[string][]byte{responseKey: append([]byte(nil), want...)},
	}

	service.handleAggregateManifestOffer(msg, offer)
	transport.mu.Lock()
	if len(transport.sent) != 1 {
		transport.mu.Unlock()
		t.Fatalf("cached ARC sends=%d want=1", len(transport.sent))
	}
	sent := transport.sent[0]
	transport.mu.Unlock()
	got, err := cvDecodeNetworkEnvelope(sent.Body, cfg.SID, cfg.Epoch)
	if err != nil || sent.Tag != cvTagARCShare || !bytes.Equal(got, want) {
		t.Fatalf("cached ARC response mismatch: tag=%q err=%v", sent.Tag, err)
	}

	mutated := msg
	mutated.Body = append([]byte(nil), msg.Body...)
	mutated.Body[0] ^= 1
	service.handleAggregateManifestOffer(mutated, offer)
	transport.mu.Lock()
	sends := len(transport.sent)
	transport.mu.Unlock()
	if sends != 1 {
		t.Fatalf("mutated offer used exact-wire cache: sends=%d", sends)
	}
}

func TestCVComponentServiceCandidateCollectionRequiresReadyCertifiedDescriptors(t *testing.T) {
	cfg, leafContext, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 32)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{0}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentService(
		context.Background(), cfg, &leafContext, 0, transport, router, store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := service.CollectLocalComponentSet(ctx); err == nil {
		t.Fatal("component candidate collection succeeded below n-f certified descriptors")
	}
}

func TestCVComponentReadyCertificateReselectsAfterLowerDealerArrives(t *testing.T) {
	if testing.Short() {
		t.Skip("component certificate integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 256)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 128)
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
	dealerLeaves := make([]*cvLeaf, len(nodes))
	dealerLeaves[0], dealerLeaves[1] = leaves[0], leaves[1]
	for dealer := 2; dealer < len(nodes); dealer++ {
		dealerLeaves[dealer], err = cvRandomDealerLeaf(leafContext, dealer)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, dealer := range []int{1, 2, 3} {
		if _, err := services[dealer].Disperse(ctx, dealerLeaves[dealer]); err != nil {
			t.Fatal(err)
		}
	}
	var first []*cvComponentDescriptor
	select {
	case first = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(first) != 3 || first[0].dealer != 1 || first[1].dealer != 2 || first[2].dealer != 3 {
		t.Fatalf("unexpected first ReadyCert pool: %+v", first)
	}
	if _, err := services[0].Disperse(ctx, dealerLeaves[0]); err != nil {
		t.Fatal(err)
	}
	var second []*cvComponentDescriptor
	select {
	case second = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(second) != 3 || second[0].dealer != 0 || second[1].dealer != 1 || second[2].dealer != 2 {
		t.Fatalf("ReadyCert did not reselect canonical lower pool: %+v", second)
	}
	services[0].readyCandidates <- second
	materialized, err := services[0].MaterializeFirstCertified(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if got := materialized.rlo.Header.Dealers; len(got) != cfg.FOld+1 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("materializer did not adopt the later certified prefix: %v", got)
	}
}

func TestCVComponentMaterializationKeepsOneCandidateInFlight(t *testing.T) {
	t.Setenv("RLADKR_CV_PRIMARY_POOL_GRACE_MS", "0")
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 256)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 128)
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
	dealerLeaves := make([]*cvLeaf, len(nodes))
	dealerLeaves[0], dealerLeaves[1] = leaves[0], leaves[1]
	for dealer := 2; dealer < len(nodes); dealer++ {
		dealerLeaves[dealer], err = cvRandomDealerLeaf(leafContext, dealer)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, dealer := range []int{1, 2, 3} {
		if _, err := services[dealer].Disperse(ctx, dealerLeaves[dealer]); err != nil {
			t.Fatal(err)
		}
	}
	var first []*cvComponentDescriptor
	select {
	case first = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := services[0].Disperse(ctx, dealerLeaves[0]); err != nil {
		t.Fatal(err)
	}
	var second []*cvComponentDescriptor
	select {
	case second = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	type materializeResult struct {
		value *cvMaterializedAggregate
		err   error
	}
	started := make(chan []*cvComponentDescriptor, 2)
	releaseFirst := make(chan struct{})
	want := &cvMaterializedAggregate{}
	results := make(chan materializeResult, 1)
	go func() {
		value, materializeErr := services[0].materializeFirstCertified(
			ctx,
			first,
			nil,
			func(_ context.Context, descriptors []*cvComponentDescriptor) (*cvMaterializedAggregate, error) {
				started <- append([]*cvComponentDescriptor(nil), descriptors...)
				if descriptors[0].dealer == 1 {
					<-releaseFirst
					return nil, fmt.Errorf("stale candidate")
				}
				return want, nil
			},
		)
		results <- materializeResult{value: value, err: materializeErr}
	}()

	select {
	case descriptors := <-started:
		if descriptors[0].dealer != 1 {
			t.Fatalf("first in-flight candidate starts with dealer %d, want 1", descriptors[0].dealer)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	services[0].readyCandidates <- second
	select {
	case descriptors := <-started:
		t.Fatalf("started concurrent candidate at dealer %d", descriptors[0].dealer)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	select {
	case descriptors := <-started:
		if descriptors[0].dealer != 0 {
			t.Fatalf("retry candidate starts with dealer %d, want latest dealer 0", descriptors[0].dealer)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case result := <-results:
		if result.err != nil || result.value != want {
			t.Fatalf("single-in-flight materializer result = %p, %v", result.value, result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestCVComponentPrimaryGraceFallsBackWhenPrimaryDoesNotMaterialize(t *testing.T) {
	if testing.Short() {
		t.Skip("component fallback integration test")
	}
	t.Setenv("RLADKR_CV_PRIMARY_GRACE_MS", "1")
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 256)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 128)
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

	third, err := cvRandomDealerLeaf(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for dealer, leaf := range []*cvLeaf{leaves[0], leaves[1], third} {
		if _, err := services[dealer].Disperse(ctx, leaf); err != nil {
			t.Fatalf("availability-lock dealer %d: %v", dealer, err)
		}
	}
	nonPrimary := 1
	if services[nonPrimary].localNode == cvPrimaryMaterializer(cfg) {
		t.Fatal("test selected the epoch primary as fallback materializer")
	}
	candidates, err := services[nonPrimary].CollectLocalComponentSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := services[nonPrimary].MaterializeFirstCertified(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if materialized.rlo.Lock.Threshold != len(nodes)-cfg.FOld ||
		len(materialized.rlo.Lock.Certificate) == 0 {
		t.Fatal("non-primary fallback did not recover an ARC certificate")
	}
	if got, want := transport.sentCount(cvTagAggregateManifest), len(nodes)-1; got != want {
		t.Fatalf("fallback materializer sent %d aggregate offers, want %d", got, want)
	}
}

func TestCVAggregateOfferFromSenderInFlight(t *testing.T) {
	processing := map[string]struct{}{
		"header-a/3": {},
		"header-b/7": {},
	}
	if !cvAggregateOfferFromSenderInFlight(processing, 3) {
		t.Fatal("missed in-flight offer from deterministic primary")
	}
	if cvAggregateOfferFromSenderInFlight(processing, 1) {
		t.Fatal("unrelated sender delayed primary fallback")
	}
	delete(processing, "header-a/3")
	if cvAggregateOfferFromSenderInFlight(processing, 3) {
		t.Fatal("completed primary offer remained in flight")
	}
}

func TestCVPrimaryOfferGraceExtendsAtMostOnce(t *testing.T) {
	if !cvShouldExtendPrimaryOfferGrace(false, false, false, true) {
		t.Fatal("first in-flight primary offer did not extend fallback grace")
	}
	if cvShouldExtendPrimaryOfferGrace(false, false, true, true) {
		t.Fatal("primary offer extended fallback grace more than once")
	}
	if cvShouldExtendPrimaryOfferGrace(true, false, false, true) {
		t.Fatal("deterministic primary delayed its own materialization")
	}
	if cvShouldExtendPrimaryOfferGrace(false, true, false, true) {
		t.Fatal("active fallback materializer renewed primary grace")
	}
	if cvShouldExtendPrimaryOfferGrace(false, false, false, false) {
		t.Fatal("missing primary offer renewed fallback grace")
	}
}

func TestCVComponentMaterializerSkipsInvalidAvailableLeaf(t *testing.T) {
	if testing.Short() {
		t.Skip("component materializer integration test")
	}
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
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
		services[i], err = newCVComponentService(
			context.Background(), cfg, &leafContext, node, transport, router, store,
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

	bad := cvCloneLeafForTest(leaves[0])
	bad.receivers[0].receiverPublicKey = leafContext.receiverPublicKeys[1]
	bad.digest = cvLeafDigest(bad)
	if err := cvVerifyLeaf(&leafContext, bad); err == nil {
		t.Fatal("test fixture did not produce an invalid APVSS leaf")
	}
	third, err := cvRandomDealerLeaf(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for dealer, leaf := range []*cvLeaf{bad, leaves[1], third} {
		if _, err := services[dealer].Disperse(ctx, leaf); err != nil {
			t.Fatalf("availability-lock dealer %d: %v", dealer, err)
		}
	}
	candidates, err := services[3].CollectLocalComponentSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := services[3].MaterializeAndCollectARC(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if got := materialized.aggregate.dealerIDs; len(got) != cfg.FOld+1 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("materializer selected dealers %v, want [1 2]", got)
	}
	wrongSelected := candidates[:cfg.FOld+1]
	wrongRoot, err := cvComponentManifestRoot(wrongSelected)
	if err != nil {
		t.Fatal(err)
	}
	wrongHeader := materialized.rlo.Header
	wrongHeader.Dealers = []int{0, 1}
	wrongOffer := &cvAggregateManifestOffer{
		header: wrongHeader, readyRoot: cvMustReadyRootForTest(t, services[3], candidates), root: wrongRoot,
	}
	if err := services[3].resolveAggregateManifestDescriptors(wrongOffer); err == nil {
		t.Fatal("accepted aggregate offer that was not ReadyCert FirstKValid")
	}
	badKey := cvComponentKey(0, bad.digest)
	for _, service := range services {
		service.mu.Lock()
		_, cached := service.verifiedLeaves[badKey]
		service.mu.Unlock()
		if cached {
			t.Fatalf("node %d cached an invalid leaf as verified", service.localNode)
		}
	}
}

func cvMustReadyRootForTest(t testing.TB, service *cvComponentService, descriptors []*cvComponentDescriptor) []byte {
	t.Helper()
	certificate, err := cvBuildComponentReadyCertificate(service.localNode, descriptors)
	if err != nil {
		t.Fatal(err)
	}
	return certificate.root
}

func TestCVComponentServiceRejectsForgedDealerInit(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 32)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{2}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentService(
		context.Background(), cfg, &leafContext, 2, transport, router, store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	leafWire, err := cvLeafCanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	dispersal, shards, err := cvDisperseComponent(leafWire, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	artifactWire, err := cvComponentShardArtifactCanonicalBytes(&cvComponentShardArtifact{
		dealer: 0, leafDigest: leaves[0].digest, dispersal: *dispersal, shard: shards[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvComponentStatementDigest(0, leaves[0].digest, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := cfg.runtime.lockSigner.SignShare(
		1, cvComponentDealerSignatureDomain, statement,
	)
	if err != nil {
		t.Fatal(err)
	}
	initWire, err := cvComponentInitCanonicalBytes(&cvComponentInit{
		artifactWire: artifactWire,
		dealerSig:    forged,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cvEncodeNetworkEnvelope(cfg.SID, cfg.Epoch, initWire)
	if err != nil {
		t.Fatal(err)
	}
	acksBefore := transport.sentCount(cvTagComponentAck)
	if err := transport.Send(Message{From: 0, To: 2, Tag: cvTagComponentInit, Body: envelope}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := transport.sentCount(cvTagComponentAck); got != acksBefore {
		t.Fatalf("forged dealer INIT produced ACK: before=%d after=%d", acksBefore, got)
	}
}
