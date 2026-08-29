package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCVRecoveryRequestDedupe(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{}
	const key = "7:duplicate-request"
	if !service.claimRecoveryRequestScalar(key) {
		t.Fatal("first recovery request claim rejected")
	}
	if service.claimRecoveryRequestScalar(key) {
		t.Fatal("duplicate recovery request claim accepted")
	}
	service.releaseRecoveryRequestScalar(key)
	if !service.claimRecoveryRequestScalar(key) {
		t.Fatal("request was not reusable after release")
	}
}

func TestCVRecoveredComponentPayloadKeyBindsDigestAndRoot(t *testing.T) {
	ref := cvComponentRefScalar{
		Header: cvComponentHeaderScalar{
			Instance: bytes.Repeat([]byte{0x11}, 32), PayloadDigest: bytes.Repeat([]byte{0x22}, 32),
		},
		Lock: cvAPDBLockScalar{Root: bytes.Repeat([]byte{0x33}, 32)},
	}
	want := cvRecoveredComponentPayloadKeyScalar(ref)
	same := cloneComponentRefScalar(ref)
	if got := cvRecoveredComponentPayloadKeyScalar(same); got != want {
		t.Fatal("equal component refs produced different recovered-payload keys")
	}
	conflictingDigest := cloneComponentRefScalar(ref)
	conflictingDigest.Header.PayloadDigest[0] ^= 1
	if got := cvRecoveredComponentPayloadKeyScalar(conflictingDigest); got == want {
		t.Fatal("payload-digest equivocation reused a recovered-payload key")
	}
	conflictingRoot := cloneComponentRefScalar(ref)
	conflictingRoot.Lock.Root[0] ^= 1
	if got := cvRecoveredComponentPayloadKeyScalar(conflictingRoot); got == want {
		t.Fatal("APDB-root equivocation reused a recovered-payload key")
	}
}

func TestCVVerifiedComponentStoreTransfersPayloadAndDropsRecoveryCopy(t *testing.T) {
	ref := cvComponentRefScalar{
		Header: cvComponentHeaderScalar{
			DealerID: 3, Instance: bytes.Repeat([]byte{0x41}, 32),
			PayloadDigest: bytes.Repeat([]byte{0x42}, 32),
		},
		Lock: cvAPDBLockScalar{Root: bytes.Repeat([]byte{0x43}, 32)},
	}
	payload := []byte("immutable verified component payload")
	hints := []byte("immutable decoded point hints")
	digest := bytes.Repeat([]byte{0x44}, 32)
	leaf := &cvLeafScalar{DealerID: ref.Header.DealerID, Digest: append([]byte(nil), digest...)}
	key := cvRecoveredComponentPayloadKeyScalar(ref)
	service := &cvAPDBNetworkServiceScalar{
		cfg:                      cvAPDBNetworkServiceConfigScalar{OldRoster: []int{ref.Header.DealerID}},
		verifiedComponentsScalar: make(map[int]cvVerifiedComponentScalar),
	}
	service.cacheRecoveredPayloadLockedScalar(key, payload, hints)
	recovered := service.recoveredPayloadsScalar[key]
	if len(recovered.payload) == 0 || &recovered.payload[0] != &payload[0] ||
		len(recovered.hints) == 0 || &recovered.hints[0] != &hints[0] {
		t.Fatal("recovered component cache copied rather than accepted collector-owned slices")
	}
	service.storeVerifiedComponentLockedScalar(ref, digest, payload, leaf)
	entry := service.verifiedComponentsScalar[ref.Header.DealerID]
	if len(entry.payload) == 0 || &entry.payload[0] != &payload[0] {
		t.Fatal("verified component store copied rather than transferred payload ownership")
	}
	if _, ok := service.recoveredPayloadsScalar[key]; ok {
		t.Fatal("verified component store retained redundant recovered payload and hints")
	}
	digest[0] ^= 1
	if bytes.Equal(entry.leafDigest, digest) {
		t.Fatal("verified component leaf digest did not retain an independent integrity copy")
	}
}

func TestCVComponentRecoveryResponseCache(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{}
	const key = "3:lock-hash"
	if got := service.cachedComponentRecoveryResponseScalar(key); got != nil {
		t.Fatalf("unexpected cache hit: %x", got)
	}
	response := []byte("store-response")
	service.cacheComponentRecoveryResponseScalar(key, response)
	response[0] = 'X'
	got := service.cachedComponentRecoveryResponseScalar(key)
	if string(got) != "store-response" {
		t.Fatalf("cache did not copy response: %q", got)
	}
	// Cached responses are immutable and are copied by sendAsync at the queue
	// boundary; repeated reads must preserve the canonical bytes.
	if string(service.cachedComponentRecoveryResponseScalar(key)) != "store-response" {
		t.Fatal("cache bytes changed between reads")
	}
}

func TestCVValidationSignatureUsesPriorityOutbound(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{
		ctx:              context.Background(),
		outbound:         make(chan cvOutboundMessageScalar, 1),
		priorityOutbound: make(chan cvOutboundMessageScalar, 1),
	}
	statement := bytes.Repeat([]byte{0x42}, 32)
	signature := bytes.Repeat([]byte{0x24}, 48)
	if err := service.sendValidationSignatureScalar(7, statement, signature); err != nil {
		t.Fatal(err)
	}
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 1 {
		t.Fatalf("validation signature queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	message := <-service.priorityOutbound
	if message.to != 7 || message.tag != cvTagValidationSignatureScalar {
		t.Fatalf("validation signature target=%d tag=%s", message.to, message.tag)
	}
	decoded, err := cvDecodeValidationSignatureScalar(message.payload)
	if err != nil || !bytes.Equal(decoded.Statement, statement) || !bytes.Equal(decoded.Signature, signature) {
		t.Fatalf("priority validation signature decode: err=%v", err)
	}
}

func TestCVValidationResultPublicationQueuesControlFanout(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{
		ctx:              context.Background(),
		cfg:              cvAPDBNetworkServiceConfigScalar{LocalNode: 2, OldRoster: []int{0, 1, 2, 3}},
		outbound:         make(chan cvOutboundMessageScalar, 4),
		priorityOutbound: make(chan cvOutboundMessageScalar, 4),
	}
	resultWire := []byte("canonical-result-fixture")
	if err := service.publishValidationResultScalar(resultWire); err != nil {
		t.Fatal(err)
	}
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 3 {
		t.Fatalf("validation result queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	seen := make(map[int]struct{}, 3)
	for range 3 {
		message := <-service.priorityOutbound
		if message.tag != cvTagValidationResultScalar || !bytes.Equal(message.payload, resultWire) || message.to == 2 {
			t.Fatalf("validation result message: to=%d tag=%s payload=%q", message.to, message.tag, message.payload)
		}
		seen[message.to] = struct{}{}
	}
	if len(seen) != 3 {
		t.Fatalf("validation result recipients=%v", seen)
	}
}

func TestCVDecisionShareFanoutUsesPriorityOutbound(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{
		ctx:              context.Background(),
		priorityOutbound: make(chan cvOutboundMessageScalar, 4),
		outbound:         make(chan cvOutboundMessageScalar, 4),
	}
	payload := []byte("decision-share")
	service.sendPriorityFanoutScalar([]int{0, 1, 2}, 1, cvTagDecisionShareScalar, payload)
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 2 {
		t.Fatalf("decision share queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	for range 2 {
		message := <-service.priorityOutbound
		if message.tag != cvTagDecisionShareScalar || !bytes.Equal(message.payload, payload) || message.to == 1 {
			t.Fatalf("decision share message: to=%d tag=%s payload=%q", message.to, message.tag, message.payload)
		}
	}
}

func TestCVSendRecoveryRequestsWithRetryScalarRetriesOnlyMissingHolders(t *testing.T) {
	recipients := []int{0, 1, 2, 3}
	attempts := make(map[int]int, len(recipients))
	successes := make(map[int]int, len(recipients))
	ready, err := cvSendRecoveryRequestsWithRetryScalar(
		context.Background(), context.Background(), nil, recipients, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultScalar {
			results := make([]cvFanoutSendResultScalar, 0, len(current))
			for _, recipient := range current {
				attempts[recipient]++
				result := cvFanoutSendResultScalar{recipient: recipient, wireBytes: 100 + recipient}
				if recipient >= 2 && attempts[recipient] == 1 {
					result.err = errors.New("transient send failure")
				}
				if recipient == 3 {
					result.err = errors.New("holder unavailable")
				}
				results = append(results, result)
			}
			return results
		},
		func(result cvFanoutSendResultScalar) { successes[result.recipient]++ },
	)
	if err != nil || ready {
		t.Fatalf("recovery request retry: ready=%v err=%v", ready, err)
	}
	if attempts[0] != 1 || attempts[1] != 1 || attempts[2] != 2 || attempts[3] != 2 {
		t.Fatalf("unexpected per-holder attempts: %v", attempts)
	}
	if successes[0] != 1 || successes[1] != 1 || successes[2] != 1 || successes[3] != 0 {
		t.Fatalf("unexpected successful-send accounting: %v", successes)
	}
}

func TestCVSendRecoveryRequestsWithRetryScalarReportsExhaustedThreshold(t *testing.T) {
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryScalar(
		context.Background(), context.Background(), nil, []int{0, 1, 2, 3}, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultScalar {
			attempts++
			results := make([]cvFanoutSendResultScalar, 0, len(current))
			for _, recipient := range current {
				result := cvFanoutSendResultScalar{recipient: recipient, wireBytes: 100}
				if recipient >= 2 {
					result.err = errors.New("holder unavailable")
				}
				results = append(results, result)
			}
			return results
		}, nil,
	)
	if err == nil || err.Error() != "CV V2 APDB recovery reached 2 holders, need 3" {
		t.Fatalf("unexpected exhausted-retry error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("recovery request attempts=%d, want 3", attempts)
	}
}

func TestCVSendRecoveryRequestsWithRetryScalarStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryScalar(
		ctx, context.Background(), nil, []int{0, 1, 2}, 2, 4,
		func(int) time.Duration { return time.Hour },
		func(current []int) []cvFanoutSendResultScalar {
			attempts++
			cancel()
			results := make([]cvFanoutSendResultScalar, 0, len(current))
			for _, recipient := range current {
				results = append(results, cvFanoutSendResultScalar{recipient: recipient, err: errors.New("send failed")})
			}
			return results
		}, nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery request cancellation error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("recovery retried after cancellation: attempts=%d", attempts)
	}
}

func TestCVVerifiedCatalogPrewarmStartsForEligibleProposers(t *testing.T) {
	_, public := cvAgreementObjectScalarFixture(t)
	proposers, validators, err := cvDeriveEligibilitySamplesScalar(
		public.OldCommittee, public.EligibilityCoin.Value,
		public.Params.proposerSampleSize, public.Params.validatorSampleSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	primary := proposers[0]
	if len(proposers) < 2 {
		t.Fatal("test fixture did not include a sampled backup proposer")
	}
	backupProposer := proposers[1]
	// The default prewarm mode also covers sampled validators, so the negative
	// case must be a member outside both samples.
	nonEligible := -1
	for _, member := range public.OldCommittee {
		if !cvContainsID(proposers, member) && !cvContainsID(validators, member) {
			nonEligible = member
			break
		}
	}
	if nonEligible < 0 {
		t.Fatal("test fixture did not include a member outside both samples")
	}

	newService := func(localNode int) *cvAPDBNetworkServiceScalar {
		return &cvAPDBNetworkServiceScalar{
			ctx: context.Background(),
			cfg: cvAPDBNetworkServiceConfigScalar{
				SID: public.SID, Epoch: public.Epoch, LocalNode: localNode,
				OldRoster: public.OldCommittee, Params: public.Params,
			},
			coinSigner: public.CoinSigner,
		}
	}
	primaryService := newService(primary)
	if err := primaryService.setEligibilityCoin(public.EligibilityCoin); err != nil {
		t.Fatal(err)
	}
	if !primaryService.verifiedCatalogPrewarm {
		t.Fatal("primary proposer did not start verified catalog prewarm")
	}
	if err := primaryService.setEligibilityCoin(public.EligibilityCoin); err != nil {
		t.Fatal(err)
	}
	if !primaryService.verifiedCatalogPrewarm {
		t.Fatal("primary proposer lost verified catalog prewarm state")
	}

	backupService := newService(backupProposer)
	if err := backupService.setEligibilityCoin(public.EligibilityCoin); err != nil {
		t.Fatal(err)
	}
	if !backupService.verifiedCatalogPrewarm {
		t.Fatal("eligible backup proposer did not start verified catalog prewarm")
	}

	nonEligibleService := newService(nonEligible)
	if err := nonEligibleService.setEligibilityCoin(public.EligibilityCoin); err != nil {
		t.Fatal(err)
	}
	if nonEligibleService.verifiedCatalogPrewarm {
		t.Fatal("member outside both samples started verified catalog prewarm")
	}
}

func TestCVValidationRequestExactRetryUsesCachedSignatureWire(t *testing.T) {
	request := []byte("verified-validation-request")
	statementKey := "statement-key"
	shareWire := []byte("cached-validation-signature")
	from := 3
	requestKey := fmt.Sprintf("%d:%x", from, hashBytes(request))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service := &cvAPDBNetworkServiceScalar{
		ctx: ctx,
		cfg: cvAPDBNetworkServiceConfigScalar{LeafContext: &cvLeafContextScalar{}, Receivers: &cvReceiverKeyMaterialScalar{},
			Validators: &cvValidatorKeyMaterialScalar{}},
		validationRequestStatements: map[string]string{requestKey: statementKey},
		validationLocalShareWires:   map[string][]byte{statementKey: shareWire},
		priorityOutbound:            make(chan cvOutboundMessageScalar, 2),
	}

	service.handleValidationRequest(Message{From: from, Body: request})
	select {
	case sent := <-service.priorityOutbound:
		if sent.to != from || sent.tag != cvTagValidationSignatureScalar || !bytes.Equal(sent.payload, shareWire) {
			t.Fatal("validation request retry returned the wrong cached signature")
		}
	default:
		t.Fatal("validation request exact retry missed cached signature")
	}

	mutated := append([]byte(nil), request...)
	mutated[0] ^= 1
	service.handleValidationRequest(Message{From: from, Body: mutated})
	service.handleValidationRequest(Message{From: from + 1, Body: request})
	select {
	case <-service.priorityOutbound:
		t.Fatal("mutated or different-sender validation request hit exact retry cache")
	default:
	}
}

func TestCVPoolOfferExactRetryUsesCachedShareWire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	from := 2
	poolWire := []byte("verified-pool-wire")
	shareWire := []byte("cached-pool-share")
	service := &cvAPDBNetworkServiceScalar{
		ctx: ctx,
		poolSlots: map[int]*cvNetworkPoolSlotScalar{from: {
			poolWire: append([]byte(nil), poolWire...), localShareWire: append([]byte(nil), shareWire...),
		}},
		outbound: make(chan cvOutboundMessageScalar, 2),
	}

	service.handlePoolOffer(Message{From: from, Body: poolWire})
	select {
	case sent := <-service.outbound:
		if sent.to != from || sent.tag != cvTagPoolCertShareScalar || !bytes.Equal(sent.payload, shareWire) {
			t.Fatal("pool offer retry returned the wrong cached share")
		}
	default:
		t.Fatal("pool offer exact retry missed cached share")
	}

	mutated := append([]byte(nil), poolWire...)
	mutated[0] ^= 1
	service.handlePoolOffer(Message{From: from, Body: mutated})
	service.handlePoolOffer(Message{From: from + 1, Body: poolWire})
	select {
	case <-service.outbound:
		t.Fatal("mutated or different-sender pool offer hit exact retry cache")
	default:
	}
}

func TestCVValidatorPrewarmModeDefaultsAndOverrides(t *testing.T) {
	t.Setenv("RLADKR_VALIDATOR_PREWARM", "")
	for _, test := range []struct {
		rosterSize int
		want       cvValidatorPrewarmModeScalar
	}{
		{rosterSize: 16, want: cvValidatorPrewarmFullScalar},
		{rosterSize: 31, want: cvValidatorPrewarmFullScalar},
		{rosterSize: 32, want: cvValidatorPrewarmFullScalar},
		{rosterSize: 128, want: cvValidatorPrewarmFullScalar},
		{rosterSize: 129, want: cvValidatorPrewarmRecoverScalar},
	} {
		if got := cvValidatorPrewarmModeFromEnvScalar(test.rosterSize); got != test.want {
			t.Fatalf("validator prewarm default for n=%d: got %d, want %d", test.rosterSize, got, test.want)
		}
	}

	for value, want := range map[string]cvValidatorPrewarmModeScalar{
		"full":    cvValidatorPrewarmFullScalar,
		"recover": cvValidatorPrewarmRecoverScalar,
		"off":     cvValidatorPrewarmOffScalar,
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("RLADKR_VALIDATOR_PREWARM", value)
			if got := cvValidatorPrewarmModeFromEnvScalar(64); got != want {
				t.Fatalf("validator prewarm override %q: got %d, want %d", value, got, want)
			}
		})
	}
}

func TestCVAPDBNetworkServiceScalarLockAndRecoverOverAuthenticatedRouter(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthScalarFixture(t)
	_, public := cvAgreementObjectScalarFixture(t)
	contextDigest := public.ContextDigest
	poolDigest := hashBytes([]byte("network APDB pool"))
	selectionDigest := hashBytes([]byte("network APDB selection"))
	proposer := cfg.OldCommittee[0]
	instance, err := cvAggregateInstanceDigestScalar(contextDigest, proposer, poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated APDB network payload")
	encoded, err := cvAPDBEncodeScalar(instance, payload, public.Params.recoveryThreshold, len(cfg.OldCommittee), 2048)
	if err != nil {
		t.Fatal(err)
	}

	localNodes := append([]int(nil), cfg.OldCommittee...)
	localReceiver := cfg.NewCommittee[0]
	localNodes = sortedUnique(append(localNodes, localReceiver))
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 256)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, localNodes, 128, auth)
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
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: encoded.shardBytes, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceScalar, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if !cvMemberInRosterScalar(node, cfg.OldCommittee) {
			localStore = nil
		}
		services[node], err = newCVAPDBNetworkServiceScalar(context.Background(), nodeCfg, transport, router, auth,
			localStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
		if err != nil {
			t.Fatalf("start node %d APDB network service: %v", node, err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	invocation, err := cvEligibilityCoinInvocationScalar(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	type coinResult struct {
		output *cvCoinOutputScalar
		err    error
	}
	coinResults := make(chan coinResult, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		go func(node int) {
			output, coinErr := services[node].EligibilityCoin(ctx)
			coinResults <- coinResult{output: output, err: coinErr}
		}(member)
	}
	var coinValue []byte
	for range cfg.OldCommittee {
		result := <-coinResults
		if result.err != nil {
			t.Fatalf("network eligibility coin: %v", result.err)
		}
		if err := cvVerifyCoinOutputScalar(result.output, invocation, public.CoinSigner); err != nil {
			t.Fatal(err)
		}
		if coinValue == nil {
			coinValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(coinValue, result.output.Value) {
			t.Fatal("network coin nodes derived different outputs")
		}
	}
	minimumCoinShares := len(cfg.OldCommittee) * (len(cfg.OldCommittee) - 1)
	if got := transport.sentCount(cvTagCoinShareScalar); got < minimumCoinShares {
		t.Fatalf("network coin sent only %d shares, need at least %d", got, minimumCoinShares)
	}

	lock, err := services[proposer].Lock(ctx, encoded)
	if err != nil {
		t.Fatalf("network LockPD: %v", err)
	}
	if cvVerifyAPDBLockScalar(lock, public.APDBSigner) != nil {
		t.Fatal("network LockPD produced an invalid compact lock")
	}
	if got := transport.sentCount(cvTagAPDBStoreScalar); got != len(cfg.OldCommittee) {
		t.Fatalf("LockPD sent %d stores, want all %d holders", got, len(cfg.OldCommittee))
	}

	componentRecovered, err := services[cfg.OldCommittee[1]].RecoverComponent(ctx, lock, nil)
	if err != nil || !bytes.Equal(componentRecovered, payload) {
		t.Fatalf("network component recovery: %v", err)
	}
	if got := transport.sentCount(cvTagAPDBRecoverGetScalar); got != len(cfg.OldCommittee) {
		t.Fatalf("component recovery sent %d requests, want all %d holders", got, len(cfg.OldCommittee))
	}

	payloadDigest, err := cvAggregatePayloadDigestScalar(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := cvAggregateHeaderScalar{
		ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: poolDigest, SelectionDigest: selectionDigest,
		AggregateDigest: hashBytes([]byte("network aggregate")), PayloadDigest: payloadDigest,
		APDBInstance: instance, APDBRoot: encoded.root,
	}
	decisionStatement, err := cvDecisionStatementScalar(contextDigest, &header, lock)
	if err != nil {
		t.Fatal(err)
	}
	handoff := cvHandoffScalar{
		ContextDigest: contextDigest, Header: header, ARC: *lock,
		DecCert: cvRecoverThresholdCertificateScalarForTest(t, public.ControlSigner, public.OldCommittee,
			cvDecisionCertificateScalarDomain, decisionStatement),
	}
	request, err := cvAggregateRecoveryRequestScalarCanonicalBytes(&cvAggregateRecoveryRequestScalar{Handoff: handoff})
	if err != nil {
		t.Fatal(err)
	}
	aggregateRecovered, err := services[localReceiver].RecoverAggregate(ctx, request, nil)
	if err != nil || !bytes.Equal(aggregateRecovered, payload) {
		t.Fatalf("network aggregate recovery: %v", err)
	}
	wantAggregateRequests := min(len(cfg.OldCommittee), public.Params.recoveryThreshold+cvAggregateRecoveryFirstWaveExtraScalar)
	if got := transport.sentCount(cvTagAggregateRecoverGetScalar); got != wantAggregateRequests {
		t.Fatalf("aggregate recovery sent %d requests, want rotated first wave %d", got, wantAggregateRequests)
	}
	if got := transport.sentCount(cvTagAggregatePayloadGetScalar); got != 1 {
		t.Fatalf("aggregate recovery fast path sent %d requests without a cache, want one before fallback", got)
	}

	providers := services[localReceiver].aggregatePayloadPullProvidersScalar(&handoff)
	if len(providers) == 0 || services[providers[0]] == nil {
		t.Fatalf("aggregate payload pull has no local test provider: %v", providers)
	}
	if err := services[providers[0]].rememberVerifiedAggregatePayloadScalar(instance, lock.Root, payload); err != nil {
		t.Fatal(err)
	}
	beforeFallbackRequests := transport.sentCount(cvTagAggregateRecoverGetScalar)
	aggregateRecovered, err = services[localReceiver].RecoverAggregate(ctx, request, nil)
	if err != nil || !bytes.Equal(aggregateRecovered, payload) {
		t.Fatalf("network aggregate cached payload pull: %v", err)
	}
	if got := transport.sentCount(cvTagAggregateRecoverGetScalar); got != beforeFallbackRequests {
		t.Fatalf("cached aggregate payload pull issued %d fallback requests", got-beforeFallbackRequests)
	}
	if got := transport.sentCount(cvTagAggregatePayloadScalar); got != 1 {
		t.Fatalf("cached aggregate payload pull received %d payload responses, want one", got)
	}
}

func TestCVAggregatePayloadResponseScalarCanonicalFraming(t *testing.T) {
	instance := hashBytes([]byte("aggregate payload instance"))
	payload := []byte("canonical aggregate payload")
	wire, err := cvAggregatePayloadResponseScalarCanonicalBytes(instance, payload, 1024)
	if err != nil {
		t.Fatal(err)
	}
	gotInstance, gotPayload, err := cvDecodeAggregatePayloadResponseScalar(wire, 1024)
	if err != nil || !bytes.Equal(gotInstance, instance) || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decode aggregate payload response: instance=%x payload=%q err=%v", gotInstance, gotPayload, err)
	}
	if _, _, err := cvDecodeAggregatePayloadResponseScalar(append(wire, 0), 1024); err == nil {
		t.Fatal("accepted non-canonical aggregate payload response")
	}
}

func TestCVAggregatePayloadPullScalarRequiresOriginalARCRoot(t *testing.T) {
	instance := hashBytes([]byte("aggregate pull root instance"))
	payload := []byte("aggregate pull root payload")
	encoded, err := cvAPDBEncodeScalar(instance, payload, 2, 4, 1024)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cvAggregatePayloadDigestScalar(payload)
	if err != nil {
		t.Fatal(err)
	}
	service := &cvAPDBNetworkServiceScalar{cfg: cvAPDBNetworkServiceConfigScalar{
		DataShards: 2, TotalShards: 4, ShardBytes: encoded.shardBytes, MaximumPayload: 1024,
	}}
	handoff := &cvHandoffScalar{
		Header: cvAggregateHeaderScalar{PayloadDigest: digest},
		ARC:    cvAPDBLockScalar{InstanceDigest: instance, Root: append([]byte(nil), encoded.root...)},
	}
	if err := service.validatePulledAggregatePayloadScalar(handoff, payload, nil); err != nil {
		t.Fatalf("valid pulled aggregate payload: %v", err)
	}
	handoff.ARC.Root[0] ^= 1
	if err := service.validatePulledAggregatePayloadScalar(handoff, payload, nil); err == nil {
		t.Fatal("accepted pulled aggregate payload under a different ARC root")
	}
}

func TestCVRotatedAggregateRecoveryFirstWaveScalar(t *testing.T) {
	recipients := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := cvRotatedAggregateRecoveryFirstWaveScalar(recipients, 7, 3)
	want := []int{3, 4, 5, 6, 7, 8, 9}
	if !equalInts(got, want) {
		t.Fatalf("rotated aggregate wave = %v, want %v", got, want)
	}
	if gotAll := cvRotatedAggregateRecoveryFirstWaveScalar(recipients, 20, 8); len(gotAll) != len(recipients) ||
		len(sortedUnique(gotAll)) != len(recipients) {
		t.Fatalf("capped aggregate wave = %v, want every holder once", gotAll)
	}
}

func TestCVAggregateRecoveryCancelBindsReceiverAndRequest(t *testing.T) {
	request := []byte("authorized aggregate recovery request")
	wire, err := cvAggregateRecoveryCancelScalarCanonicalBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cvDecodeAggregateRecoveryCancelScalar(wire)
	if err != nil || digest != string(hashBytes(request)) {
		t.Fatalf("decode aggregate recovery cancel: digest=%x err=%v", []byte(digest), err)
	}
	if _, err := cvDecodeAggregateRecoveryCancelScalar(append(wire, 0)); err == nil {
		t.Fatal("accepted non-canonical aggregate recovery cancel")
	}

	service := &cvAPDBNetworkServiceScalar{
		aggregateRecoveryActiveScalar: make(map[cvAggregateRecoveryRequestKeyScalar]bool),
	}
	owner := cvAggregateRecoveryRequestKeyScalar{receiver: 10, digest: digest}
	other := cvAggregateRecoveryRequestKeyScalar{receiver: 11, digest: digest}
	if !service.registerAggregateRecoveryRequestScalar(owner) {
		t.Fatal("failed to register aggregate recovery request")
	}
	service.cancelAggregateRecoveryRequestScalar(other)
	if service.aggregateRecoveryRequestCanceledScalar(owner) {
		t.Fatal("another receiver canceled the owner's aggregate recovery")
	}
	service.cancelAggregateRecoveryRequestScalar(owner)
	if !service.aggregateRecoveryRequestCanceledScalar(owner) {
		t.Fatal("owner's aggregate recovery cancel was ignored")
	}
}

func TestCVRecoveryWaveStopsAfterThresholdReady(t *testing.T) {
	ready := make(chan struct{}, 1)
	var waves [][]int
	completed, err := cvSendRecoveryRequestsWithWavesScalar(
		context.Background(), context.Background(), ready,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 4, 1, func(int) time.Duration { return 0 },
		[]int{3, 4, 5, 6, 7, 8, 9}, time.Millisecond,
		func(targets []int) []cvFanoutSendResultScalar {
			waves = append(waves, append([]int(nil), targets...))
			ready <- struct{}{}
			results := make([]cvFanoutSendResultScalar, len(targets))
			for i, target := range targets {
				results[i] = cvFanoutSendResultScalar{recipient: target, wireBytes: 1}
			}
			return results
		}, nil,
	)
	if err != nil || !completed || len(waves) != 1 || !equalInts(waves[0], []int{3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("recovery waves=%v completed=%t err=%v", waves, completed, err)
	}
}

func TestCVComponentRecoveryDealerFirstStopsBeforeHolderWave(t *testing.T) {
	ready := make(chan struct{}, 1)
	var sent [][]int
	completed, err := cvSendRecoveryRequestsWithScheduleScalar(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveScalar{
			{recipients: []int{2}, responseGrace: time.Second, waitAfterSend: true},
			{recipients: []int{3, 4, 5, 0}, responseGrace: time.Second},
		},
		func(targets []int) []cvFanoutSendResultScalar {
			sent = append(sent, append([]int(nil), targets...))
			ready <- struct{}{}
			return successfulCVFanoutResultsScalar(targets)
		}, nil,
	)
	if err != nil || !completed || len(sent) != 1 || !equalInts(sent[0], []int{2}) {
		t.Fatalf("dealer-first sends=%v completed=%t err=%v", sent, completed, err)
	}
}

func TestCVComponentRecoveryDealerFirstExpandsToHolderWave(t *testing.T) {
	ready := make(chan struct{}, 1)
	var sent [][]int
	completed, err := cvSendRecoveryRequestsWithScheduleScalar(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveScalar{
			{recipients: []int{2}, responseGrace: time.Millisecond, waitAfterSend: true},
			{recipients: []int{3, 4, 5, 0}, responseGrace: time.Second},
		},
		func(targets []int) []cvFanoutSendResultScalar {
			sent = append(sent, append([]int(nil), targets...))
			if len(sent) == 2 {
				ready <- struct{}{}
			}
			return successfulCVFanoutResultsScalar(targets)
		}, nil,
	)
	if err != nil || !completed || len(sent) != 2 || !equalInts(sent[0], []int{2}) ||
		!equalInts(sent[1], []int{3, 4, 5, 0}) {
		t.Fatalf("dealer-first fallback sends=%v completed=%t err=%v", sent, completed, err)
	}
}

func TestCVComponentRecoveryDealerFirstFallsBackAfterHolderFailure(t *testing.T) {
	ready := make(chan struct{}, 1)
	var sent [][]int
	completed, err := cvSendRecoveryRequestsWithScheduleScalar(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveScalar{
			{recipients: []int{2}, responseGrace: time.Millisecond, waitAfterSend: true},
			{recipients: []int{3, 4, 5}, responseGrace: time.Millisecond},
		},
		func(targets []int) []cvFanoutSendResultScalar {
			sent = append(sent, append([]int(nil), targets...))
			results := successfulCVFanoutResultsScalar(targets)
			if len(sent) == 2 {
				for i := range results {
					results[i].err = fmt.Errorf("holder unavailable")
				}
			}
			return results
		}, nil,
	)
	if err != nil || completed || len(sent) != 3 || !equalInts(sent[2], []int{0, 1, 3, 4, 5}) {
		t.Fatalf("dealer-first final fallback sends=%v completed=%t err=%v", sent, completed, err)
	}
}

func TestCVComponentRecoveryScheduleEnvironment(t *testing.T) {
	t.Setenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE", "dealer-first")
	t.Setenv("RLADKR_COMPONENT_DIRECT_GRACE_MS", "17")
	t.Setenv("RLADKR_COMPONENT_DEALER_RESPONSE", "drop")
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryDealerFirstScalar {
		t.Fatalf("schedule=%q, want dealer-first", got)
	}
	if got := CVComponentDirectGrace(); got != 17*time.Millisecond {
		t.Fatalf("direct grace=%v, want 17ms", got)
	}
	if got := CVComponentDealerResponseMode(); got != cvComponentDealerResponseDropScalar {
		t.Fatalf("dealer response=%q, want drop", got)
	}
	t.Setenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE", "invalid")
	t.Setenv("RLADKR_COMPONENT_DIRECT_GRACE_MS", "invalid")
	t.Setenv("RLADKR_COMPONENT_DEALER_RESPONSE", "invalid")
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryDealerFirstScalar {
		t.Fatalf("invalid schedule=%q, want dealer-first", got)
	}
	if got := CVComponentDirectGrace(); got != cvComponentDirectGraceDefaultScalar {
		t.Fatalf("invalid direct grace=%v, want %v", got, cvComponentDirectGraceDefaultScalar)
	}
	if got := CVComponentDirectGraceForCommittee(32); got != cvComponentDirectGraceLargeScalar {
		t.Fatalf("invalid n32 direct grace=%v, want %v", got, cvComponentDirectGraceLargeScalar)
	}
	if got := CVComponentDealerResponseMode(); got != cvComponentDealerResponseNormalScalar {
		t.Fatalf("invalid dealer response=%q, want normal", got)
	}
	t.Setenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE", "hedged")
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryHedgedScalar {
		t.Fatalf("explicit schedule=%q, want hedged", got)
	}
}

func successfulCVFanoutResultsScalar(targets []int) []cvFanoutSendResultScalar {
	results := make([]cvFanoutSendResultScalar, len(targets))
	for i, target := range targets {
		results[i] = cvFanoutSendResultScalar{recipient: target, wireBytes: 1}
	}
	return results
}

func TestCVAPDBNetworkServiceScalarRejectsMissingAuthentication(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthScalarFixture(t)
	_, public := cvAgreementObjectScalarFixture(t)
	nodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(nodes, 16)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, []int{cfg.OldCommittee[0]}, 8, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	serviceCfg := cvAPDBNetworkServiceConfigScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), LocalNode: cfg.OldCommittee[0],
		OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee, ExpectedContext: public.ContextDigest,
		TotalShards: len(cfg.OldCommittee), DataShards: public.Params.recoveryThreshold,
		ShardBytes: 32, MaximumPayload: 1024,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	holderStore, err := newCVAPDBHolderStoreScalar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCVAPDBNetworkServiceScalar(context.Background(), serviceCfg, transport, router, nil,
		holderStore, public.APDBSigner, public.ControlSigner, public.CoinSigner); err == nil {
		t.Fatal("started V2 APDB network service without an authenticator")
	}
}

func TestCVAPDBNetworkServiceScalarCertifiesEligiblePool(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthScalarFixture(t)
	object, public := cvAgreementObjectScalarFixture(t)
	transport := newCVRouterTestTransport(cfg.OldCommittee, 256)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 128, auth)
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
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceScalar, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		memberCfg := serviceCfg
		memberCfg.LocalNode = member
		services[member], err = newCVAPDBNetworkServiceScalar(context.Background(), memberCfg, transport, router, auth,
			holderStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type certifiedResult struct {
		pool *cvPoolScalar
		cert *cvPoolCertificateScalar
		err  error
	}
	results := make(chan certifiedResult, len(cfg.OldCommittee)-1)
	for _, member := range cfg.OldCommittee {
		if member == object.Pool.ProposerID {
			continue
		}
		go func(node int) {
			pool, cert, waitErr := services[node].AwaitCertifiedPool(ctx, object.Pool.ProposerID)
			results <- certifiedResult{pool: pool, cert: cert, err: waitErr}
		}(member)
	}
	certificate, err := services[object.Pool.ProposerID].CertifyPool(ctx, &object.Pool)
	if err != nil {
		t.Fatalf("certify V2 pool: %v", err)
	}
	if err := cvVerifyPoolCertificateScalar(&object.Pool, certificate, public.ControlSigner); err != nil {
		t.Fatal(err)
	}
	for range len(cfg.OldCommittee) - 1 {
		result := <-results
		if result.err != nil || !bytes.Equal(result.pool.Digest, object.Pool.Digest) ||
			cvVerifyPoolCertificateScalar(result.pool, result.cert, public.ControlSigner) != nil {
			t.Fatalf("await certified V2 pool: %v", result.err)
		}
	}
	if got := transport.sentCount(cvTagPoolOfferScalar); got < len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d offers", got)
	}
	if got := transport.sentCount(cvTagPoolCertShareScalar); got < public.ControlSigner.Threshold()-1 {
		t.Fatalf("pool certification returned %d shares", got)
	}
	if got := transport.sentCount(cvTagPoolCertScalar); got != len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d certificates", got)
	}
	offersAfterCertification := transport.sentCount(cvTagPoolOfferScalar)
	certificatesAfterCertification := transport.sentCount(cvTagPoolCertScalar)
	time.Sleep(2 * cvControlRetryIntervalScalar)
	if got := transport.sentCount(cvTagPoolOfferScalar); got != offersAfterCertification {
		t.Fatalf("pool offers continued after certification: before=%d after=%d", offersAfterCertification, got)
	}
	if got := transport.sentCount(cvTagPoolCertScalar); got != certificatesAfterCertification {
		t.Fatalf("pool certificates continued after certification: before=%d after=%d", certificatesAfterCertification, got)
	}

	badCertificate := *certificate
	badCertificate.Certificate = append([]byte(nil), certificate.Certificate...)
	badCertificate.Certificate[0] ^= 1
	if _, err := services[cfg.OldCommittee[0]].ContributorCoin(ctx, &object.Pool, &badCertificate); err == nil {
		t.Fatal("released contributor coin share without a valid PoolCert")
	}
	type contributorResult struct {
		output *cvCoinOutputScalar
		err    error
	}
	contributorResults := make(chan contributorResult, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		go func(node int) {
			output, coinErr := services[node].ContributorCoin(ctx, &object.Pool, certificate)
			contributorResults <- contributorResult{output: output, err: coinErr}
		}(member)
	}
	contributorInvocation, err := cvContributorCoinInvocationScalar(public.ContextDigest, object.Pool.ProposerID, object.Pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var contributorValue []byte
	for range cfg.OldCommittee {
		result := <-contributorResults
		if result.err != nil || cvVerifyCoinOutputScalar(result.output, contributorInvocation, public.CoinSigner) != nil {
			t.Fatalf("network contributor coin: %v", result.err)
		}
		if contributorValue == nil {
			contributorValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(contributorValue, result.output.Value) {
			t.Fatal("network contributor coin outputs differ")
		}
	}

	proposers, _, err := cvDeriveEligibilitySamplesScalar(cfg.OldCommittee, public.EligibilityCoin.Value,
		public.Params.proposerSampleSize, public.Params.validatorSampleSize)
	if err != nil {
		t.Fatal(err)
	}
	eligible := nodeSet(proposers)
	nonEligible := -1
	for _, member := range cfg.OldCommittee {
		if _, ok := eligible[member]; !ok {
			nonEligible = member
			break
		}
	}
	if nonEligible >= 0 {
		nonEligiblePool, err := cvBuildPoolScalar(public.ContextDigest, nonEligible, object.Pool.Components, public.Params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := services[nonEligible].CertifyPool(ctx, nonEligiblePool); err == nil {
			t.Fatal("certified a pool from a non-eligible proposer")
		}
	}
}

func TestCVAPDBNetworkServiceScalarFinalizesDecisionAndRelaysHandoff(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthScalarFixture(t)
	object, public := cvAgreementObjectScalarFixture(t)
	receiver := cfg.NewCommittee[0]
	localNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), receiver))
	transport := newCVRouterTestTransport(localNodes, 512)
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
	decisionRoot := t.TempDir()
	serviceCfg := cvAPDBNetworkServiceConfigScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceScalar, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if node == receiver {
			localStore = nil
		} else {
			nodeCfg.DecisionStore, err = newCVDecisionSignStoreScalar(decisionRoot)
			if err != nil {
				t.Fatal(err)
			}
		}
		services[node], err = newCVAPDBNetworkServiceScalar(context.Background(), nodeCfg, transport, router, auth,
			localStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handoffResult := make(chan error, 1)
	go func() {
		handoff, waitErr := services[receiver].AwaitHandoff(ctx)
		if waitErr == nil {
			waitErr = cvVerifyHandoffScalar(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
		}
		handoffResult <- waitErr
	}()
	finalized := make(chan error, len(cfg.OldCommittee))
	finalize := func(member int) {
		go func(node int) {
			handoff, finalizeErr := services[node].FinalizeDecision(ctx, object)
			if finalizeErr == nil {
				finalizeErr = cvVerifyHandoffScalar(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
			}
			finalized <- finalizeErr
		}(member)
	}
	threshold := public.ControlSigner.Threshold()
	for _, member := range cfg.OldCommittee[:threshold] {
		finalize(member)
	}
	for range threshold {
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
	}
	// The remaining old node enters finalization only after a recovered
	// certificate has already been relayed and cached.
	for _, member := range cfg.OldCommittee[threshold:] {
		finalize(member)
	}
	for range len(cfg.OldCommittee) - threshold {
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-handoffResult; err != nil {
		t.Fatal(err)
	}
	if got := transport.sentCount(cvTagDecisionShareScalar); got < len(cfg.OldCommittee)*(public.ControlSigner.Threshold()-1) {
		t.Fatalf("decision phase sent only %d shares", got)
	}
	minimumHandoffs := len(cfg.OldCommittee) + len(cfg.NewCommittee) - 1
	if got := transport.sentCount(cvTagHandoffScalar); got < minimumHandoffs {
		t.Fatalf("decision phase sent only %d handoffs", got)
	}
}
