package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type cvLaneSendFailureTransport struct {
	*cvRouterTestTransport
	failedReceiver int
}

func TestCVLeafScalarCompactACKOwnershipSizeN32(t *testing.T) {
	oldRoster := make([]int, 32)
	newRoster := make([]int, 32)
	for i := range oldRoster {
		oldRoster[i] = i
		newRoster[i] = 32 + i
	}
	context := &cvLeafContextScalar{
		SID: "cv-leaf-size-n32", Epoch: 1, OldRoster: oldRoster, NewRoster: newRoster,
		ReceiverRegistryDigest: hashBytes([]byte("cv-leaf-size-n32-registry")),
		SharingDegree:          21, Profile: cvChunkProfile{chunkBits: 8, maxComponents: 11},
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	fullBytes, err := cvLeafWireSizeScalar(context, chunks, 0)
	if err != nil {
		t.Fatal(err)
	}
	pointBytes := bls12381.SizeOfG1AffineCompressed
	ownershipProofBytes := cvFramedWireSizeScalar(len(cvOwnershipProofWireDomainScalar)) +
		2*cvPointVectorWireSizeScalar(chunks) + 3*pointBytes +
		2*cvScalarVectorWireSizeScalar(chunks) + 2*fr.Bytes
	duplicatedBytes := len(newRoster) * cvFramedWireSizeScalar(ownershipProofBytes)
	compactBytes := fullBytes - duplicatedBytes
	if compactBytes <= 0 || duplicatedBytes <= 0 || compactBytes >= fullBytes {
		t.Fatalf("invalid compact ACK ownership estimate: full=%d compact=%d duplicate=%d", fullBytes, compactBytes, duplicatedBytes)
	}
	t.Logf("n32 all-ACK leaf full=%d compact=%d duplicate=%d reduction=%.2f%%",
		fullBytes, compactBytes, duplicatedBytes, 100*float64(duplicatedBytes)/float64(fullBytes))
}

func (t *cvLaneSendFailureTransport) Send(msg Message) error {
	if msg.Tag == cvTagLaneOfferScalar && msg.To == t.failedReceiver {
		t.mu.Lock()
		t.sent = append(t.sent, Message{From: msg.From, To: msg.To, Tag: msg.Tag, Body: append([]byte(nil), msg.Body...)})
		t.mu.Unlock()
		return fmt.Errorf("receiver %d unavailable", msg.To)
	}
	return t.cvRouterTestTransport.Send(msg)
}

func TestCVScalarNetworkLeafCompletesWithFNewSilentReceivers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 quorum/fallback proof generation in short mode")
	}
	cfg := cvScalarParamsTestConfig()
	params, err := cvDeriveScalarParams(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic := filepath.Join(t.TempDir(), "receiver-public")
	receiverSecret := filepath.Join(t.TempDir(), "receiver-secret")
	if err := cvGenerateReceiverRegistryScalar(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee); err != nil {
		t.Fatal(err)
	}
	validatorPublic := filepath.Join(t.TempDir(), "validator-public")
	validatorSecret := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryScalar(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	thresholdPublic := filepath.Join(t.TempDir(), "threshold-public")
	thresholdSecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleScalar(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryScalar(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, cfg.NewCommittee)
	if err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryScalar(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleScalar(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.coin)
	auth, err := newCVNetworkAuthenticatorScalar(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	leafContext := &cvLeafContextScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ReceiverRegistryDigest: receivers.registryDigest, SharingDegree: params.newShareDegree,
		Profile: cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	contextDigest, err := cvLeafContextDigestScalar(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	dealer := cfg.OldCommittee[0]
	silentReceiver := cfg.NewCommittee[len(cfg.NewCommittee)-1]
	localNodes := sortedUnique(append([]int{dealer}, cfg.NewCommittee...))
	transport := &cvLaneSendFailureTransport{
		cvRouterTestTransport: newCVRouterTestTransport(localNodes, 512),
		failedReceiver:        silentReceiver,
	}
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, localNodes, 256, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreScalar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: 0, MaximumPayload: cvMaxLeafWireBytes, Params: params,
		LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceScalar, len(localNodes))
	for _, node := range localNodes {
		if node == silentReceiver {
			continue
		}
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterScalar(node, cfg.NewCommittee) {
			localStore = nil
			nodeCfg.Receivers, err = cvLoadReceiverRegistryScalar(
				receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, []int{node},
			)
			if err != nil {
				t.Fatal(err)
			}
			nodeCfg.Validators, err = cvLoadValidatorRegistryScalar(
				validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, nil,
			)
		} else {
			nodeCfg.Receivers, err = cvLoadReceiverRegistryScalar(
				receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			nodeCfg.Validators, err = cvLoadValidatorRegistryScalar(
				validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, []int{node},
			)
		}
		if err != nil {
			t.Fatal(err)
		}
		services[node], err = newCVAPDBNetworkServiceScalar(context.Background(), nodeCfg, transport, router, auth,
			localStore, apdbSigner, controlSigner, coinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	material, err := services[dealer].BuildLeafMaterialScalar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	leaf := material.leaf
	canonical, err := cvLeafScalarCanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil || !bytes.Equal(canonical, material.wire) {
		t.Fatalf("built leaf material is not canonical: %v", err)
	}
	if _, _, _, wireBytes, err := cvLeafExperimentMetricsFromWireScalar(leaf, material.wire, leafContext); err != nil || wireBytes != len(canonical) {
		t.Fatalf("built leaf material metrics mismatch: wire=%d want=%d err=%v", wireBytes, len(canonical), err)
	}
	tampered := *material
	tampered.wire = append([]byte(nil), material.wire...)
	tampered.wire[len(tampered.wire)-1] ^= 1
	if _, err := services[dealer].PublishBuiltComponentScalar(ctx, &tampered); err == nil {
		t.Fatal("component publisher accepted tampered built leaf wire")
	}
	otherDealer := cfg.OldCommittee[0]
	if otherDealer == dealer {
		otherDealer = cfg.OldCommittee[1]
	}
	if _, err := services[otherDealer].PublishBuiltComponentScalar(ctx, material); err == nil {
		t.Fatal("component publisher accepted built leaf material from another service")
	}
	if err := cvVerifyAPVSSScalar(leaf, leafContext, receivers, validators); err != nil {
		t.Fatal(err)
	}
	if len(services[dealer].cfg.Receivers.localEncryptionSecrets) != 0 ||
		len(services[dealer].cfg.Receivers.localIdentitySecrets) != 0 ||
		len(services[dealer].cfg.Validators.localSecrets) != 1 {
		t.Fatal("network V2 dealer actor received non-local secrets")
	}
	for _, receiver := range cfg.NewCommittee {
		if receiver == silentReceiver {
			continue
		}
		if len(services[receiver].cfg.Receivers.localEncryptionSecrets) != 1 ||
			len(services[receiver].cfg.Receivers.localIdentitySecrets) != 1 ||
			len(services[receiver].cfg.Validators.localSecrets) != 0 {
			t.Fatalf("network V2 receiver %d received non-local secrets", receiver)
		}
	}
	if len(leaf.Partition.ACKReceiverIndices) != params.newShareThreshold ||
		len(leaf.Partition.FallbackReceiverIndices) != params.newFaults {
		t.Fatal("network V2 leaf did not freeze the first ACK quorum")
	}
	if len(leaf.Partition.FallbackReceiverIndices) != 1 ||
		leaf.Partition.FallbackReceiverIndices[0] != len(cfg.NewCommittee) {
		t.Fatal("network V2 leaf did not assign the silent receiver to fallback")
	}
	wire, err := cvLeafScalarCanonicalBytes(leaf, receivers, validators)
	if err != nil || 8+len(wire) > params.recoveryThreshold*services[dealer].cfg.ShardBytes {
		t.Fatalf("fallback leaf exceeds configured shard capacity: wire=%d shard=%d err=%v",
			len(wire), services[dealer].cfg.ShardBytes, err)
	}
	if got := transport.sentCount(cvTagLaneOfferScalar); got != len(cfg.NewCommittee) {
		t.Fatalf("network V2 dealer sent %d offers", got)
	}
	if got := transport.sentCount(cvTagLaneACKScalar); got != params.newShareThreshold {
		t.Fatalf("network V2 receivers sent %d ACKs", got)
	}
}

func TestCVLaneNetworkScalarIgnoresLateACKAfterFreeze(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	pending := &cvPendingLaneACKsScalar{
		offers: make([]*cvReceiverLaneOfferScalar, len(leaf.Receivers)),
		acks: map[int]*cvACKEvidenceScalar{
			1: leaf.Receivers[0].ACK,
			2: leaf.Receivers[1].ACK,
			3: leaf.Receivers[2].ACK,
		},
		quorum: 3, frozen: true, ready: make(chan struct{}, 1),
	}
	for i := range leaf.Receivers {
		pending.offers[i] = &leaf.Receivers[i].Offer
	}
	service := &cvAPDBNetworkServiceScalar{
		cfg: cvAPDBNetworkServiceConfigScalar{
			LocalNode: leaf.DealerID, NewRoster: append([]int(nil), context.NewRoster...),
			LeafContext: context, Receivers: receivers, Validators: validators,
		},
		pendingLaneACKsScalar: pending,
	}
	lateIndex := len(context.NewRoster)
	lateOffer := pending.offers[lateIndex-1]
	offerWire, err := cvReceiverLaneOfferScalarCanonicalBytes(
		context, leaf.DealerID, lateOffer, &receivers.encryptionPublicKeys[lateIndex-1],
	)
	if err != nil {
		t.Fatal(err)
	}
	message := &cvLaneACKMessageScalar{
		DealerID: leaf.DealerID, ReceiverID: context.NewRoster[lateIndex-1], ReceiverIndex: lateIndex,
		OfferDigest: cvLaneOfferDigestScalar(offerWire), Evidence: *leaf.Receivers[lateIndex-1].ACK,
	}
	wire, err := cvLaneACKMessageScalarCanonicalBytes(message, context)
	if err != nil {
		t.Fatal(err)
	}
	service.handleLaneACKScalar(Message{From: message.ReceiverID, To: leaf.DealerID, Body: wire})
	if len(pending.acks) != pending.quorum {
		t.Fatal("late ACK changed the frozen CV V2 quorum")
	}
	if _, accepted := pending.acks[lateIndex]; accepted {
		t.Fatal("late ACK entered the frozen CV V2 leaf")
	}
}

func TestCVLaneACKMessageScalarStrictCodecAndBinding(t *testing.T) {
	leaf, context, receivers, _ := cvAllACKLeafScalarFixture(t)
	offer := &leaf.Receivers[0].Offer
	offerWire, err := cvReceiverLaneOfferScalarCanonicalBytes(context, leaf.DealerID, offer, &receivers.encryptionPublicKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	message := &cvLaneACKMessageScalar{
		DealerID: leaf.DealerID, ReceiverID: offer.ReceiverID, ReceiverIndex: offer.ReceiverIndex,
		OfferDigest: cvLaneOfferDigestScalar(offerWire), Evidence: *leaf.Receivers[0].ACK,
	}
	wire, err := cvLaneACKMessageScalarCanonicalBytes(message, context)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLaneACKMessageScalar(wire, context)
	if err != nil || decoded.DealerID != message.DealerID || decoded.ReceiverID != message.ReceiverID {
		t.Fatalf("round-trip CV V2 lane ACK message: %v", err)
	}
	if _, err := cvDecodeLaneACKMessageScalar(append(append([]byte(nil), wire...), 0), context); err == nil {
		t.Fatal("accepted trailing CV V2 lane ACK message bytes")
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	decoded, err = cvDecodeLaneACKMessageScalar(mutated, context)
	if err == nil && cvVerifyACKScalar(context, message.DealerID, offer, &receivers.encryptionPublicKeys[0],
		receivers.identityPublicKeys[0], &decoded.Evidence) == nil {
		t.Fatal("accepted mutated CV V2 lane ACK evidence")
	}
}

func TestCVComponentNetworkScalarVerifiedCatalogSkipsInvalidPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 component publication barrier in short mode")
	}
	_, leafContext, receivers, validators := cvAllACKLeafScalarFixture(t)
	cfg := cvScalarParamsTestConfig()
	params, err := cvDeriveScalarParams(cfg)
	if err != nil {
		t.Fatal(err)
	}
	thresholdPublic := filepath.Join(t.TempDir(), "threshold-public")
	thresholdSecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleScalar(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleScalar(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromScalarMaterial(bundle.coin)
	auth, err := newCVNetworkAuthenticatorScalar(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestScalar(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	shardBytes, err := cvEpochShardBytesUpperBoundScalar(
		leafContext, params, receivers, validators, params.recoveryThreshold,
	)
	if err != nil {
		t.Fatal(err)
	}
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 8192)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, allNodes, 4096, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreScalar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: shardBytes, MaximumPayload: cvMaxLeafWireBytes, Params: params, LeafContext: leafContext,
		Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceScalar, len(allNodes))
	for _, node := range allNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterScalar(node, cfg.NewCommittee) {
			localStore = nil
		}
		services[node], err = newCVAPDBNetworkServiceScalar(context.Background(), nodeCfg, transport, router, auth,
			localStore, apdbSigner, controlSigner, coinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	invalidDealer := cfg.OldCommittee[0]
	invalidPayload := []byte("valid APDB payload that is not a CV V2 leaf")
	invalidInstance, err := cvComponentInstanceDigestScalar(contextDigest, invalidDealer)
	if err != nil {
		t.Fatal(err)
	}
	invalidEncoded, err := cvAPDBEncodeSizedScalar(
		invalidInstance, invalidPayload, params.recoveryThreshold, len(cfg.OldCommittee), shardBytes, cvMaxLeafWireBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	invalidLock, err := services[invalidDealer].Lock(ctx, invalidEncoded)
	if err != nil {
		t.Fatal(err)
	}
	invalidRef := cvComponentRefScalar{Header: cvComponentHeaderScalar{
		ContextDigest: append([]byte(nil), contextDigest...), DealerID: invalidDealer,
		PayloadDigest: cvComponentPayloadDigestScalar(invalidPayload), Instance: invalidInstance,
		Root: append([]byte(nil), invalidLock.Root...),
	}, Lock: *invalidLock}
	invalidWire, err := cvComponentRefScalarCanonicalBytes(invalidRef)
	if err != nil {
		t.Fatal(err)
	}
	services[invalidDealer].storeComponentRefScalar(invalidRef)
	for _, member := range cfg.OldCommittee[1:] {
		if err := services[invalidDealer].send(member, cvTagComponentRefScalar, invalidWire); err != nil {
			t.Fatal(err)
		}
	}

	published := make(chan error, len(cfg.OldCommittee)-1)
	for _, dealer := range cfg.OldCommittee[1:] {
		go func(node int) {
			if node == cfg.OldCommittee[1] {
				leaf, buildErr := services[node].BuildLeafScalar(ctx)
				if buildErr == nil {
					_, buildErr = services[node].PublishComponentScalar(ctx, leaf)
				}
				published <- buildErr
				return
			}
			material, buildErr := services[node].BuildLeafMaterialScalar(ctx)
			if buildErr == nil {
				_, buildErr = services[node].PublishBuiltComponentScalar(ctx, material)
			}
			published <- buildErr
		}(dealer)
	}
	for range cfg.OldCommittee[1:] {
		if err := <-published; err != nil {
			t.Fatal(err)
		}
	}
	var proposerCatalog []cvComponentRefScalar
	for _, member := range cfg.OldCommittee {
		refs, err := services[member].AwaitVerifiedComponentCatalogScalar(ctx)
		if err != nil || len(refs) != params.poolSize {
			t.Fatalf("old member %d verified component barrier: refs=%d err=%v", member, len(refs), err)
		}
		for i := range refs {
			if refs[i].Header.DealerID == invalidDealer {
				t.Fatalf("old actor %d accepted non-leaf APDB payload", member)
			}
			if i > 0 && refs[i-1].Header.DealerID >= refs[i].Header.DealerID {
				t.Fatalf("old actor %d froze a non-canonical verified catalog", member)
			}
		}
		if member == cfg.OldCommittee[0] {
			proposerCatalog = refs
		}
	}
	recoveriesBeforeCachedCatalog := transport.sentCount(cvTagAPDBRecoverGetScalar)
	cachedCatalog, err := services[cfg.OldCommittee[0]].AwaitVerifiedComponentCatalogScalar(ctx)
	if err != nil || len(cachedCatalog) != params.poolSize {
		t.Fatalf("read cached verified catalog: refs=%d err=%v", len(cachedCatalog), err)
	}
	if recoveriesAfter := transport.sentCount(cvTagAPDBRecoverGetScalar); recoveriesAfter != recoveriesBeforeCachedCatalog {
		t.Fatalf("cached verified catalog triggered recovery: before=%d after=%d", recoveriesBeforeCachedCatalog, recoveriesAfter)
	}
	for i := range cachedCatalog {
		if !equalComponentRefsScalar(cachedCatalog[i], proposerCatalog[i]) {
			t.Fatalf("cached verified catalog changed component %d", i)
		}
	}
	pool, err := cvBuildPoolScalar(contextDigest, cfg.OldCommittee[0], proposerCatalog, params)
	if err != nil {
		t.Fatal(err)
	}
	selected := make([]int, params.componentCount)
	for i := range selected {
		selected[i] = i
	}
	recoveriesBefore := transport.sentCount(cvTagAPDBRecoverGetScalar)
	leaves, err := services[cfg.OldCommittee[0]].VerifiedComponentLeavesScalar(pool, selected)
	if err != nil || len(leaves) != params.componentCount {
		t.Fatalf("read selected verified components: leaves=%d err=%v", len(leaves), err)
	}
	if recoveriesAfter := transport.sentCount(cvTagAPDBRecoverGetScalar); recoveriesAfter != recoveriesBefore {
		t.Fatalf("verified component cache triggered recovery: before=%d after=%d", recoveriesBefore, recoveriesAfter)
	}
	mutatedRefs := cloneComponentRefsScalar(pool.Components)
	mutatedRefs[len(mutatedRefs)-1].Header.Root[0] ^= 1
	mutatedRefs[len(mutatedRefs)-1].Lock.Root[0] ^= 1
	mutatedPool, err := cvBuildPoolScalar(contextDigest, cfg.OldCommittee[0], mutatedRefs, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services[cfg.OldCommittee[0]].VerifiedComponentLeavesScalar(mutatedPool, selected); err == nil {
		t.Fatal("verified component cache accepted a mutated Pool reference")
	}
	duplicateSelection := append([]int(nil), selected...)
	duplicateSelection[len(duplicateSelection)-1] = duplicateSelection[0]
	if _, err := services[cfg.OldCommittee[0]].VerifiedComponentLeavesScalar(pool, duplicateSelection); err == nil {
		t.Fatal("verified component cache accepted duplicate selected indices")
	}
}
