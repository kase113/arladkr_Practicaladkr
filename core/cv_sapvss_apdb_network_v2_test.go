package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestCVRecoveryRequestDedupe(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{}
	const key = "7:duplicate-request"
	if !service.claimRecoveryRequestV2(key) {
		t.Fatal("first recovery request claim rejected")
	}
	if service.claimRecoveryRequestV2(key) {
		t.Fatal("duplicate recovery request claim accepted")
	}
	service.releaseRecoveryRequestV2(key)
	if !service.claimRecoveryRequestV2(key) {
		t.Fatal("request was not reusable after release")
	}
}

func TestCVRecoveredComponentPayloadKeyBindsDigestAndRoot(t *testing.T) {
	ref := cvComponentRefV2{
		Header: cvComponentHeaderV2{
			Instance: bytes.Repeat([]byte{0x11}, 32), PayloadDigest: bytes.Repeat([]byte{0x22}, 32),
		},
		Lock: cvAPDBLockV2{Root: bytes.Repeat([]byte{0x33}, 32)},
	}
	want := cvRecoveredComponentPayloadKeyV2(ref)
	same := cloneComponentRefV2(ref)
	if got := cvRecoveredComponentPayloadKeyV2(same); got != want {
		t.Fatal("equal component refs produced different recovered-payload keys")
	}
	conflictingDigest := cloneComponentRefV2(ref)
	conflictingDigest.Header.PayloadDigest[0] ^= 1
	if got := cvRecoveredComponentPayloadKeyV2(conflictingDigest); got == want {
		t.Fatal("payload-digest equivocation reused a recovered-payload key")
	}
	conflictingRoot := cloneComponentRefV2(ref)
	conflictingRoot.Lock.Root[0] ^= 1
	if got := cvRecoveredComponentPayloadKeyV2(conflictingRoot); got == want {
		t.Fatal("APDB-root equivocation reused a recovered-payload key")
	}
}

func TestCVVerifiedComponentStoreTransfersPayloadAndDropsRecoveryCopy(t *testing.T) {
	ref := cvComponentRefV2{
		Header: cvComponentHeaderV2{
			DealerID: 3, Instance: bytes.Repeat([]byte{0x41}, 32),
			PayloadDigest: bytes.Repeat([]byte{0x42}, 32),
		},
		Lock: cvAPDBLockV2{Root: bytes.Repeat([]byte{0x43}, 32)},
	}
	payload := []byte("immutable verified component payload")
	hints := []byte("immutable decoded point hints")
	digest := bytes.Repeat([]byte{0x44}, 32)
	leaf := &cvLeafV2{DealerID: ref.Header.DealerID, Digest: append([]byte(nil), digest...)}
	key := cvRecoveredComponentPayloadKeyV2(ref)
	service := &cvAPDBNetworkServiceV2{
		cfg:                  cvAPDBNetworkServiceConfigV2{OldRoster: []int{ref.Header.DealerID}},
		verifiedComponentsV2: make(map[int]cvVerifiedComponentV2),
	}
	service.cacheRecoveredPayloadLockedV2(key, payload, hints)
	recovered := service.recoveredPayloadsV2[key]
	if len(recovered.payload) == 0 || &recovered.payload[0] != &payload[0] ||
		len(recovered.hints) == 0 || &recovered.hints[0] != &hints[0] {
		t.Fatal("recovered component cache copied rather than accepted collector-owned slices")
	}
	service.storeVerifiedComponentLockedV2(ref, digest, payload, leaf)
	entry := service.verifiedComponentsV2[ref.Header.DealerID]
	if len(entry.payload) == 0 || &entry.payload[0] != &payload[0] {
		t.Fatal("verified component store copied rather than transferred payload ownership")
	}
	if _, ok := service.recoveredPayloadsV2[key]; ok {
		t.Fatal("verified component store retained redundant recovered payload and hints")
	}
	digest[0] ^= 1
	if bytes.Equal(entry.leafDigest, digest) {
		t.Fatal("verified component leaf digest did not retain an independent integrity copy")
	}
}

func TestCVComponentRecoveryResponseCache(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{}
	const key = "3:lock-hash"
	if got := service.cachedComponentRecoveryResponseV2(key); got != nil {
		t.Fatalf("unexpected cache hit: %x", got)
	}
	response := []byte("store-response")
	service.cacheComponentRecoveryResponseV2(key, response)
	response[0] = 'X'
	got := service.cachedComponentRecoveryResponseV2(key)
	if string(got) != "store-response" {
		t.Fatalf("cache did not copy response: %q", got)
	}
	// Cached responses are immutable and are copied by sendAsync at the queue
	// boundary; repeated reads must preserve the canonical bytes.
	if string(service.cachedComponentRecoveryResponseV2(key)) != "store-response" {
		t.Fatal("cache bytes changed between reads")
	}
}

func TestCVValidationSignatureUsesPriorityOutbound(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{
		ctx:              context.Background(),
		outbound:         make(chan cvOutboundMessageV2, 1),
		priorityOutbound: make(chan cvOutboundMessageV2, 1),
	}
	statement := bytes.Repeat([]byte{0x42}, 32)
	signature := bytes.Repeat([]byte{0x24}, 48)
	if err := service.sendValidationSignatureV2(7, statement, signature); err != nil {
		t.Fatal(err)
	}
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 1 {
		t.Fatalf("validation signature queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	message := <-service.priorityOutbound
	if message.to != 7 || message.tag != cvTagValidationSignatureV2 {
		t.Fatalf("validation signature target=%d tag=%s", message.to, message.tag)
	}
	decoded, err := cvDecodeValidationSignatureV2(message.payload)
	if err != nil || !bytes.Equal(decoded.Statement, statement) || !bytes.Equal(decoded.Signature, signature) {
		t.Fatalf("priority validation signature decode: err=%v", err)
	}
}

func TestCVValidationResultPublicationQueuesControlFanout(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{
		ctx:              context.Background(),
		cfg:              cvAPDBNetworkServiceConfigV2{LocalNode: 2, OldRoster: []int{0, 1, 2, 3}},
		outbound:         make(chan cvOutboundMessageV2, 4),
		priorityOutbound: make(chan cvOutboundMessageV2, 4),
	}
	resultWire := []byte("canonical-result-fixture")
	if err := service.publishValidationResultV2(resultWire); err != nil {
		t.Fatal(err)
	}
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 3 {
		t.Fatalf("validation result queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	seen := make(map[int]struct{}, 3)
	for range 3 {
		message := <-service.priorityOutbound
		if message.tag != cvTagValidationResultV2 || !bytes.Equal(message.payload, resultWire) || message.to == 2 {
			t.Fatalf("validation result message: to=%d tag=%s payload=%q", message.to, message.tag, message.payload)
		}
		seen[message.to] = struct{}{}
	}
	if len(seen) != 3 {
		t.Fatalf("validation result recipients=%v", seen)
	}
}

func TestCVDecisionShareFanoutUsesPriorityOutbound(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{
		ctx:              context.Background(),
		priorityOutbound: make(chan cvOutboundMessageV2, 4),
		outbound:         make(chan cvOutboundMessageV2, 4),
	}
	payload := []byte("decision-share")
	service.sendPriorityFanoutV2([]int{0, 1, 2}, 1, cvTagDecisionShareV2, payload)
	if len(service.outbound) != 0 || len(service.priorityOutbound) != 2 {
		t.Fatalf("decision share queues: normal=%d priority=%d", len(service.outbound), len(service.priorityOutbound))
	}
	for range 2 {
		message := <-service.priorityOutbound
		if message.tag != cvTagDecisionShareV2 || !bytes.Equal(message.payload, payload) || message.to == 1 {
			t.Fatalf("decision share message: to=%d tag=%s payload=%q", message.to, message.tag, message.payload)
		}
	}
}

func TestCVSendRecoveryRequestsWithRetryV2RetriesOnlyMissingHolders(t *testing.T) {
	recipients := []int{0, 1, 2, 3}
	attempts := make(map[int]int, len(recipients))
	successes := make(map[int]int, len(recipients))
	ready, err := cvSendRecoveryRequestsWithRetryV2(
		context.Background(), context.Background(), nil, recipients, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultV2 {
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				attempts[recipient]++
				result := cvFanoutSendResultV2{recipient: recipient, wireBytes: 100 + recipient}
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
		func(result cvFanoutSendResultV2) { successes[result.recipient]++ },
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

func TestCVSendRecoveryRequestsWithRetryV2ReportsExhaustedThreshold(t *testing.T) {
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryV2(
		context.Background(), context.Background(), nil, []int{0, 1, 2, 3}, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultV2 {
			attempts++
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				result := cvFanoutSendResultV2{recipient: recipient, wireBytes: 100}
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

func TestCVSendRecoveryRequestsWithRetryV2StopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryV2(
		ctx, context.Background(), nil, []int{0, 1, 2}, 2, 4,
		func(int) time.Duration { return time.Hour },
		func(current []int) []cvFanoutSendResultV2 {
			attempts++
			cancel()
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				results = append(results, cvFanoutSendResultV2{recipient: recipient, err: errors.New("send failed")})
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
	_, public := cvAgreementObjectV2Fixture(t)
	proposers, validators, err := cvDeriveEligibilitySamplesV2(
		public.OldCommittee, public.EligibilityCoin.Value,
		public.Params.proposerSampleSize, public.Params.validatorSampleSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	primary := proposers[0]
	backupOnly := -1
	for _, proposer := range proposers[1:] {
		if !cvContainsID(validators, proposer) {
			backupOnly = proposer
			break
		}
	}
	if backupOnly < 0 {
		t.Fatal("test fixture did not include a backup-only proposer")
	}
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

	newService := func(localNode int) *cvAPDBNetworkServiceV2 {
		return &cvAPDBNetworkServiceV2{
			ctx: context.Background(),
			cfg: cvAPDBNetworkServiceConfigV2{
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

	backupService := newService(backupOnly)
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
	service := &cvAPDBNetworkServiceV2{
		ctx: ctx,
		cfg: cvAPDBNetworkServiceConfigV2{LeafContext: &cvLeafContextV2{}, Receivers: &cvReceiverKeyMaterialV2{},
			Validators: &cvValidatorKeyMaterialV2{}},
		validationRequestStatements: map[string]string{requestKey: statementKey},
		validationLocalShareWires:   map[string][]byte{statementKey: shareWire},
		priorityOutbound:            make(chan cvOutboundMessageV2, 2),
	}

	service.handleValidationRequest(Message{From: from, Body: request})
	select {
	case sent := <-service.priorityOutbound:
		if sent.to != from || sent.tag != cvTagValidationSignatureV2 || !bytes.Equal(sent.payload, shareWire) {
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
	service := &cvAPDBNetworkServiceV2{
		ctx: ctx,
		poolSlots: map[int]*cvNetworkPoolSlotV2{from: {
			poolWire: append([]byte(nil), poolWire...), localShareWire: append([]byte(nil), shareWire...),
		}},
		outbound: make(chan cvOutboundMessageV2, 2),
	}

	service.handlePoolOffer(Message{From: from, Body: poolWire})
	select {
	case sent := <-service.outbound:
		if sent.to != from || sent.tag != cvTagPoolCertShareV2 || !bytes.Equal(sent.payload, shareWire) {
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
		want       cvValidatorPrewarmModeV2
	}{
		{rosterSize: 16, want: cvValidatorPrewarmFullV2},
		{rosterSize: 31, want: cvValidatorPrewarmFullV2},
		{rosterSize: 32, want: cvValidatorPrewarmFullV2},
		{rosterSize: 128, want: cvValidatorPrewarmFullV2},
		{rosterSize: 129, want: cvValidatorPrewarmRecoverV2},
	} {
		if got := cvValidatorPrewarmModeFromEnvV2(test.rosterSize); got != test.want {
			t.Fatalf("validator prewarm default for n=%d: got %d, want %d", test.rosterSize, got, test.want)
		}
	}

	for value, want := range map[string]cvValidatorPrewarmModeV2{
		"full":    cvValidatorPrewarmFullV2,
		"recover": cvValidatorPrewarmRecoverV2,
		"off":     cvValidatorPrewarmOffV2,
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("RLADKR_VALIDATOR_PREWARM", value)
			if got := cvValidatorPrewarmModeFromEnvV2(64); got != want {
				t.Fatalf("validator prewarm override %q: got %d, want %d", value, got, want)
			}
		})
	}
}

func TestCVAPDBNetworkServiceV2BuildsVCertAfterRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real APVSS aggregate validation network test in short mode")
	}
	t.Setenv("RLADKR_VALIDATION_FIRST_WAVE_GRACE_MS", "10000")
	first, leafContext, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, cfg.OldCommittee[i], leafContext, receivers, validators))
	}
	publicDir := filepath.Join(t.TempDir(), "threshold-public")
	secretDir := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: leafContext, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(cfg.OldCommittee, 4096)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 2048, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: reference.Components[0].encoded.shardBytes, MaximumPayload: cvMaxLeafWireBytes,
		Params: params, EligibilityCoin: &reference.EligibilityCoin,
		LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		memberCfg := serviceCfg
		memberCfg.LocalNode = member
		services[member], err = newCVAPDBNetworkServiceV2(context.Background(), memberCfg, transport, router, auth,
			holderStore, apdbSigner, controlSigner, coinSigner)
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
	proposer := reference.Header.ProposerID
	for i := range reference.Components {
		lock, lockErr := services[proposer].Lock(ctx, reference.Components[i].encoded)
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		reference.Pool.Components[i].Lock = *lock
	}
	aggregateEncoded, err := cvAPDBEncodeSizedV2(reference.Header.APDBInstance, reference.AggregatePayload,
		params.recoveryThreshold, len(cfg.OldCommittee), serviceCfg.ShardBytes, cvMaxLeafWireBytes)
	if err != nil {
		t.Fatal(err)
	}
	header := reference.Header
	header.APDBRoot = append([]byte(nil), aggregateEncoded.root...)
	arc, err := services[proposer].Lock(ctx, aggregateEncoded)
	if err != nil {
		t.Fatal(err)
	}
	request := &cvValidationRequestV2{
		Header: header, Pool: reference.Pool, PoolCert: reference.PoolCert,
		ContributorCoin: reference.ContributorCoin, SelectedIndices: reference.SelectedIndices, ARC: *arc,
	}
	resultCh := make(chan error, len(cfg.OldCommittee)-1)
	for _, member := range cfg.OldCommittee {
		if member == proposer {
			continue
		}
		go func(node int) {
			certificate, waitErr := services[node].AwaitValidationResult(ctx, request)
			if waitErr == nil {
				waitErr = cvVerifyValidationCertificateV2(certificate, &request.Header,
					services[node].validatorSample, params.validatorThreshold, validators)
			}
			resultCh <- waitErr
		}(member)
	}
	certificate, err := services[proposer].CertifyAggregate(ctx, request)
	if err != nil {
		t.Fatalf("network VCert: %v", err)
	}
	if err := cvVerifyValidationCertificateV2(certificate, &request.Header,
		services[proposer].validatorSample, params.validatorThreshold, validators); err != nil {
		t.Fatal(err)
	}
	for range len(cfg.OldCommittee) - 1 {
		if err := <-resultCh; err != nil {
			t.Fatal(err)
		}
	}
	firstWave, deferredWave := cvValidationRequestWavesV2(
		services[proposer].validatorSample, params.validatorThreshold, proposer,
	)
	for _, member := range cfg.OldCommittee {
		if cvContainsID(firstWave, member) {
			if got := transport.sentCountFromTo(cvTagValidationRequestV2, proposer, member); got < 1 {
				t.Fatalf("first-wave validator %d received %d validation requests, want at least one", member, got)
			}
			continue
		}
		if cvContainsID(deferredWave, member) {
			if got := transport.sentCountFromTo(cvTagValidationRequestV2, proposer, member); got != 0 {
				t.Fatalf("deferred validator %d received %d validation requests after first-wave quorum", member, got)
			}
			continue
		}
		if got := transport.sentCountFromTo(cvTagValidationRequestV2, proposer, member); got != 0 {
			t.Fatalf("non-validator %d received %d validation requests, want none", member, got)
		}
	}
}

func TestCVValidationRequestWavesV2RotateAndCoverSample(t *testing.T) {
	sample := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	first, deferred := cvValidationRequestWavesV2(sample, 4, 3)
	if !equalInts(first, []int{3, 4, 5, 6, 7, 8}) || !equalInts(deferred, []int{9, 0, 1, 2}) {
		t.Fatalf("validation waves first=%v deferred=%v", first, deferred)
	}
	covered := append(append([]int(nil), first...), deferred...)
	if len(covered) != len(sample) || len(sortedUnique(covered)) != len(sample) {
		t.Fatalf("validation waves do not cover sample exactly once: %v", covered)
	}
	first, deferred = cvValidationRequestWavesV2(sample, 9, 8)
	if len(first) != len(sample) || len(deferred) != 0 {
		t.Fatalf("capped validation waves first=%v deferred=%v", first, deferred)
	}
}

func TestCVValidationRequestWaveScheduleStopsOrExpands(t *testing.T) {
	first := []int{3, 4, 5, 6, 7, 8}
	deferred := []int{9, 0, 1, 2}
	ready := make(chan struct{}, 1)
	var sent [][]int
	complete, err := cvSendValidationRequestWavesV2(
		context.Background(), context.Background(), ready, first, deferred, time.Second,
		func(recipients []int) {
			sent = append(sent, append([]int(nil), recipients...))
			ready <- struct{}{}
		},
	)
	if err != nil || !complete || len(sent) != 1 || !equalInts(sent[0], first) {
		t.Fatalf("completed validation schedule sent=%v complete=%t err=%v", sent, complete, err)
	}

	ready = make(chan struct{}, 1)
	sent = nil
	complete, err = cvSendValidationRequestWavesV2(
		context.Background(), context.Background(), ready, first, deferred, time.Millisecond,
		func(recipients []int) { sent = append(sent, append([]int(nil), recipients...)) },
	)
	if err != nil || complete || len(sent) != 2 || !equalInts(sent[0], first) || !equalInts(sent[1], deferred) {
		t.Fatalf("expanded validation schedule sent=%v complete=%t err=%v", sent, complete, err)
	}
}

func TestCVAPDBNetworkServiceV2ReceiversPersistBeforeExchangingScalarShares(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 receiver recovery network test in short mode")
	}
	first, leafContext, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, cfg.OldCommittee[i], leafContext, receivers, validators))
	}
	publicDir := filepath.Join(t.TempDir(), "threshold-public")
	secretDir := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.coin)
	reference, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: leafContext, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 4096)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, allNodes, 2048, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	aggregateEncoded, err := cvAPDBEncodeV2(reference.Header.APDBInstance, reference.AggregatePayload,
		params.recoveryThreshold, len(cfg.OldCommittee), cvMaxLeafWireBytes)
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: aggregateEncoded.shardBytes, MaximumPayload: cvMaxLeafWireBytes, Params: params,
		EligibilityCoin: &reference.EligibilityCoin, LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(allNodes))
	failingReceiver := cfg.NewCommittee[0]
	for _, node := range allNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterV2(node, cfg.NewCommittee) {
			localStore = nil
			nodeCfg.ScalarStore, err = newCVScalarStoreV2(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if node == failingReceiver {
				blocker := filepath.Dir(filepath.Dir(nodeCfg.ScalarStore.path(cfg.SID, uint64(cfg.Epoch), node)))
				if err := os.WriteFile(blocker, []byte("block scalar state directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
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
	proposer := reference.Header.ProposerID
	arc, err := services[proposer].Lock(ctx, aggregateEncoded)
	if err != nil {
		t.Fatal(err)
	}
	header := reference.Header
	header.APDBRoot = append([]byte(nil), arc.Root...)
	statement, err := cvDecisionStatementV2(contextDigest, &header, arc)
	if err != nil {
		t.Fatal(err)
	}
	handoff := &cvHandoffV2{ContextDigest: contextDigest, Header: header, ARC: *arc,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, controlSigner, cfg.OldCommittee, cvDecisionCertificateV2Domain, statement)}
	type receiverResult struct {
		node   int
		public bls12381.G1Affine
		err    error
	}
	results := make(chan receiverResult, len(cfg.NewCommittee))
	for _, receiver := range cfg.NewCommittee {
		go func(node int) {
			_, _, _, publicKey, recoverErr := services[node].RecoverAndExchangeScalarShare(ctx, handoff)
			results <- receiverResult{node: node, public: publicKey, err: recoverErr}
		}(receiver)
	}
	var publicKey bls12381.G1Affine
	havePublicKey := false
	for i := 0; i < len(cfg.NewCommittee); i++ {
		result := <-results
		if result.node == failingReceiver {
			if result.err == nil {
				t.Fatal("receiver released a scalar share after persistence failure")
			}
			continue
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !havePublicKey {
			publicKey = result.public
			havePublicKey = true
		} else if !publicKey.Equal(&result.public) {
			t.Fatal("CV V2 receivers recovered different public keys")
		}
	}
	if !havePublicKey || !publicKey.Equal(&reference.PublicKey) {
		t.Fatal("network receiver public key differs from reference recovery")
	}
	if cvContainsID(transport.sentFromByTag(cvTagAggregateShareV2), failingReceiver) {
		t.Fatal("receiver broadcast a public scalar output after persistence failure")
	}
	services[failingReceiver].mu.Lock()
	localOutputCount := len(services[failingReceiver].localScalarOutputs)
	services[failingReceiver].mu.Unlock()
	if localOutputCount != 0 {
		t.Fatal("receiver registered a public scalar output after persistence failure")
	}
}

func TestCVAPDBNetworkServiceV2LockAndRecoverOverAuthenticatedRouter(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	_, public := cvAgreementObjectV2Fixture(t)
	contextDigest := public.ContextDigest
	poolDigest := hashBytes([]byte("network APDB pool"))
	selectionDigest := hashBytes([]byte("network APDB selection"))
	proposer := cfg.OldCommittee[0]
	instance, err := cvAggregateInstanceDigestV2(contextDigest, proposer, poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated APDB network payload")
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(cfg.OldCommittee), 2048)
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
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: encoded.shardBytes, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if !cvMemberInRosterV2(node, cfg.OldCommittee) {
			localStore = nil
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
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
	invocation, err := cvEligibilityCoinInvocationV2(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	type coinResult struct {
		output *cvCoinOutputV2
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
		if err := cvVerifyCoinOutputV2(result.output, invocation, public.CoinSigner); err != nil {
			t.Fatal(err)
		}
		if coinValue == nil {
			coinValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(coinValue, result.output.Value) {
			t.Fatal("network coin nodes derived different outputs")
		}
	}
	minimumCoinShares := len(cfg.OldCommittee) * (len(cfg.OldCommittee) - 1)
	if got := transport.sentCount(cvTagCoinShareV2); got < minimumCoinShares {
		t.Fatalf("network coin sent only %d shares, need at least %d", got, minimumCoinShares)
	}

	lock, err := services[proposer].Lock(ctx, encoded)
	if err != nil {
		t.Fatalf("network LockPD: %v", err)
	}
	if cvVerifyAPDBLockV2(lock, public.APDBSigner) != nil {
		t.Fatal("network LockPD produced an invalid compact lock")
	}
	if got := transport.sentCount(cvTagAPDBStoreV2); got != len(cfg.OldCommittee) {
		t.Fatalf("LockPD sent %d stores, want all %d holders", got, len(cfg.OldCommittee))
	}

	componentRecovered, err := services[cfg.OldCommittee[1]].RecoverComponent(ctx, lock, nil)
	if err != nil || !bytes.Equal(componentRecovered, payload) {
		t.Fatalf("network component recovery: %v", err)
	}
	if got := transport.sentCount(cvTagAPDBRecoverGetV2); got != len(cfg.OldCommittee) {
		t.Fatalf("component recovery sent %d requests, want all %d holders", got, len(cfg.OldCommittee))
	}

	payloadDigest, err := cvAggregatePayloadDigestV2(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := cvAggregateHeaderV2{
		ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: poolDigest, SelectionDigest: selectionDigest,
		AggregateDigest: hashBytes([]byte("network aggregate")), PayloadDigest: payloadDigest,
		APDBInstance: instance, APDBRoot: encoded.root,
	}
	decisionStatement, err := cvDecisionStatementV2(contextDigest, &header, lock)
	if err != nil {
		t.Fatal(err)
	}
	handoff := cvHandoffV2{
		ContextDigest: contextDigest, Header: header, ARC: *lock,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.OldCommittee,
			cvDecisionCertificateV2Domain, decisionStatement),
	}
	request, err := cvAggregateRecoveryRequestV2CanonicalBytes(&cvAggregateRecoveryRequestV2{Handoff: handoff})
	if err != nil {
		t.Fatal(err)
	}
	aggregateRecovered, err := services[localReceiver].RecoverAggregate(ctx, request, nil)
	if err != nil || !bytes.Equal(aggregateRecovered, payload) {
		t.Fatalf("network aggregate recovery: %v", err)
	}
	wantAggregateRequests := min(len(cfg.OldCommittee), public.Params.recoveryThreshold+cvAggregateRecoveryFirstWaveExtraV2)
	if got := transport.sentCount(cvTagAggregateRecoverGetV2); got != wantAggregateRequests {
		t.Fatalf("aggregate recovery sent %d requests, want rotated first wave %d", got, wantAggregateRequests)
	}
	if got := transport.sentCount(cvTagAggregatePayloadGetV2); got != 1 {
		t.Fatalf("aggregate recovery fast path sent %d requests without a cache, want one before fallback", got)
	}

	providers := services[localReceiver].aggregatePayloadPullProvidersV2(&handoff)
	if len(providers) == 0 || services[providers[0]] == nil {
		t.Fatalf("aggregate payload pull has no local test provider: %v", providers)
	}
	if err := services[providers[0]].rememberVerifiedAggregatePayloadV2(instance, lock.Root, payload); err != nil {
		t.Fatal(err)
	}
	beforeFallbackRequests := transport.sentCount(cvTagAggregateRecoverGetV2)
	aggregateRecovered, err = services[localReceiver].RecoverAggregate(ctx, request, nil)
	if err != nil || !bytes.Equal(aggregateRecovered, payload) {
		t.Fatalf("network aggregate cached payload pull: %v", err)
	}
	if got := transport.sentCount(cvTagAggregateRecoverGetV2); got != beforeFallbackRequests {
		t.Fatalf("cached aggregate payload pull issued %d fallback requests", got-beforeFallbackRequests)
	}
	if got := transport.sentCount(cvTagAggregatePayloadV2); got != 1 {
		t.Fatalf("cached aggregate payload pull received %d payload responses, want one", got)
	}
}

func TestCVAggregatePayloadResponseV2CanonicalFraming(t *testing.T) {
	instance := hashBytes([]byte("aggregate payload instance"))
	payload := []byte("canonical aggregate payload")
	wire, err := cvAggregatePayloadResponseV2CanonicalBytes(instance, payload, 1024)
	if err != nil {
		t.Fatal(err)
	}
	gotInstance, gotPayload, err := cvDecodeAggregatePayloadResponseV2(wire, 1024)
	if err != nil || !bytes.Equal(gotInstance, instance) || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decode aggregate payload response: instance=%x payload=%q err=%v", gotInstance, gotPayload, err)
	}
	if _, _, err := cvDecodeAggregatePayloadResponseV2(append(wire, 0), 1024); err == nil {
		t.Fatal("accepted non-canonical aggregate payload response")
	}
}

func TestCVAggregatePayloadPullV2RequiresOriginalARCRoot(t *testing.T) {
	instance := hashBytes([]byte("aggregate pull root instance"))
	payload := []byte("aggregate pull root payload")
	encoded, err := cvAPDBEncodeV2(instance, payload, 2, 4, 1024)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cvAggregatePayloadDigestV2(payload)
	if err != nil {
		t.Fatal(err)
	}
	service := &cvAPDBNetworkServiceV2{cfg: cvAPDBNetworkServiceConfigV2{
		DataShards: 2, TotalShards: 4, ShardBytes: encoded.shardBytes, MaximumPayload: 1024,
	}}
	handoff := &cvHandoffV2{
		Header: cvAggregateHeaderV2{PayloadDigest: digest},
		ARC:    cvAPDBLockV2{InstanceDigest: instance, Root: append([]byte(nil), encoded.root...)},
	}
	if err := service.validatePulledAggregatePayloadV2(handoff, payload, nil); err != nil {
		t.Fatalf("valid pulled aggregate payload: %v", err)
	}
	handoff.ARC.Root[0] ^= 1
	if err := service.validatePulledAggregatePayloadV2(handoff, payload, nil); err == nil {
		t.Fatal("accepted pulled aggregate payload under a different ARC root")
	}
}

func TestCVRotatedAggregateRecoveryFirstWaveV2(t *testing.T) {
	recipients := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := cvRotatedAggregateRecoveryFirstWaveV2(recipients, 7, 3)
	want := []int{3, 4, 5, 6, 7, 8, 9}
	if !equalInts(got, want) {
		t.Fatalf("rotated aggregate wave = %v, want %v", got, want)
	}
	if gotAll := cvRotatedAggregateRecoveryFirstWaveV2(recipients, 20, 8); len(gotAll) != len(recipients) ||
		len(sortedUnique(gotAll)) != len(recipients) {
		t.Fatalf("capped aggregate wave = %v, want every holder once", gotAll)
	}
}

func TestCVAggregateRecoveryCancelBindsReceiverAndRequest(t *testing.T) {
	request := []byte("authorized aggregate recovery request")
	wire, err := cvAggregateRecoveryCancelV2CanonicalBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cvDecodeAggregateRecoveryCancelV2(wire)
	if err != nil || digest != string(hashBytes(request)) {
		t.Fatalf("decode aggregate recovery cancel: digest=%x err=%v", []byte(digest), err)
	}
	if _, err := cvDecodeAggregateRecoveryCancelV2(append(wire, 0)); err == nil {
		t.Fatal("accepted non-canonical aggregate recovery cancel")
	}

	service := &cvAPDBNetworkServiceV2{
		aggregateRecoveryActiveV2: make(map[cvAggregateRecoveryRequestKeyV2]bool),
	}
	owner := cvAggregateRecoveryRequestKeyV2{receiver: 10, digest: digest}
	other := cvAggregateRecoveryRequestKeyV2{receiver: 11, digest: digest}
	if !service.registerAggregateRecoveryRequestV2(owner) {
		t.Fatal("failed to register aggregate recovery request")
	}
	service.cancelAggregateRecoveryRequestV2(other)
	if service.aggregateRecoveryRequestCanceledV2(owner) {
		t.Fatal("another receiver canceled the owner's aggregate recovery")
	}
	service.cancelAggregateRecoveryRequestV2(owner)
	if !service.aggregateRecoveryRequestCanceledV2(owner) {
		t.Fatal("owner's aggregate recovery cancel was ignored")
	}
}

func TestCVRecoveryWaveStopsAfterThresholdReady(t *testing.T) {
	ready := make(chan struct{}, 1)
	var waves [][]int
	completed, err := cvSendRecoveryRequestsWithWavesV2(
		context.Background(), context.Background(), ready,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 4, 1, func(int) time.Duration { return 0 },
		[]int{3, 4, 5, 6, 7, 8, 9}, time.Millisecond,
		func(targets []int) []cvFanoutSendResultV2 {
			waves = append(waves, append([]int(nil), targets...))
			ready <- struct{}{}
			results := make([]cvFanoutSendResultV2, len(targets))
			for i, target := range targets {
				results[i] = cvFanoutSendResultV2{recipient: target, wireBytes: 1}
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
	completed, err := cvSendRecoveryRequestsWithScheduleV2(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveV2{
			{recipients: []int{2}, responseGrace: time.Second, waitAfterSend: true},
			{recipients: []int{3, 4, 5, 0}, responseGrace: time.Second},
		},
		func(targets []int) []cvFanoutSendResultV2 {
			sent = append(sent, append([]int(nil), targets...))
			ready <- struct{}{}
			return successfulCVFanoutResultsV2(targets)
		}, nil,
	)
	if err != nil || !completed || len(sent) != 1 || !equalInts(sent[0], []int{2}) {
		t.Fatalf("dealer-first sends=%v completed=%t err=%v", sent, completed, err)
	}
}

func TestCVComponentRecoveryDealerFirstExpandsToHolderWave(t *testing.T) {
	ready := make(chan struct{}, 1)
	var sent [][]int
	completed, err := cvSendRecoveryRequestsWithScheduleV2(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveV2{
			{recipients: []int{2}, responseGrace: time.Millisecond, waitAfterSend: true},
			{recipients: []int{3, 4, 5, 0}, responseGrace: time.Second},
		},
		func(targets []int) []cvFanoutSendResultV2 {
			sent = append(sent, append([]int(nil), targets...))
			if len(sent) == 2 {
				ready <- struct{}{}
			}
			return successfulCVFanoutResultsV2(targets)
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
	completed, err := cvSendRecoveryRequestsWithScheduleV2(
		context.Background(), context.Background(), ready, []int{0, 1, 2, 3, 4, 5}, 3, 1,
		func(int) time.Duration { return 0 },
		[]cvRecoveryRequestWaveV2{
			{recipients: []int{2}, responseGrace: time.Millisecond, waitAfterSend: true},
			{recipients: []int{3, 4, 5}, responseGrace: time.Millisecond},
		},
		func(targets []int) []cvFanoutSendResultV2 {
			sent = append(sent, append([]int(nil), targets...))
			results := successfulCVFanoutResultsV2(targets)
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
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryDealerFirstV2 {
		t.Fatalf("schedule=%q, want dealer-first", got)
	}
	if got := CVComponentDirectGrace(); got != 17*time.Millisecond {
		t.Fatalf("direct grace=%v, want 17ms", got)
	}
	if got := CVComponentDealerResponseMode(); got != cvComponentDealerResponseDropV2 {
		t.Fatalf("dealer response=%q, want drop", got)
	}
	t.Setenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE", "invalid")
	t.Setenv("RLADKR_COMPONENT_DIRECT_GRACE_MS", "invalid")
	t.Setenv("RLADKR_COMPONENT_DEALER_RESPONSE", "invalid")
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryDealerFirstV2 {
		t.Fatalf("invalid schedule=%q, want dealer-first", got)
	}
	if got := CVComponentDirectGrace(); got != cvComponentDirectGraceDefaultV2 {
		t.Fatalf("invalid direct grace=%v, want %v", got, cvComponentDirectGraceDefaultV2)
	}
	if got := CVComponentDirectGraceForCommittee(32); got != cvComponentDirectGraceLargeV2 {
		t.Fatalf("invalid n32 direct grace=%v, want %v", got, cvComponentDirectGraceLargeV2)
	}
	if got := CVComponentDealerResponseMode(); got != cvComponentDealerResponseNormalV2 {
		t.Fatalf("invalid dealer response=%q, want normal", got)
	}
	t.Setenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE", "hedged")
	if got := CVComponentRecoverySchedule(); got != cvComponentRecoveryHedgedV2 {
		t.Fatalf("explicit schedule=%q, want hedged", got)
	}
}

func successfulCVFanoutResultsV2(targets []int) []cvFanoutSendResultV2 {
	results := make([]cvFanoutSendResultV2, len(targets))
	for i, target := range targets {
		results[i] = cvFanoutSendResultV2{recipient: target, wireBytes: 1}
	}
	return results
}

func TestCVAPDBNetworkServiceV2RejectsMissingAuthentication(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	_, public := cvAgreementObjectV2Fixture(t)
	nodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(nodes, 16)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, []int{cfg.OldCommittee[0]}, 8, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), LocalNode: cfg.OldCommittee[0],
		OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee, ExpectedContext: public.ContextDigest,
		TotalShards: len(cfg.OldCommittee), DataShards: public.Params.recoveryThreshold,
		ShardBytes: 32, MaximumPayload: 1024,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCVAPDBNetworkServiceV2(context.Background(), serviceCfg, transport, router, nil,
		holderStore, public.APDBSigner, public.ControlSigner, public.CoinSigner); err == nil {
		t.Fatal("started V2 APDB network service without an authenticator")
	}
}

func TestCVAPDBNetworkServiceV2CertifiesEligiblePool(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	object, public := cvAgreementObjectV2Fixture(t)
	transport := newCVRouterTestTransport(cfg.OldCommittee, 256)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 128, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		memberCfg := serviceCfg
		memberCfg.LocalNode = member
		services[member], err = newCVAPDBNetworkServiceV2(context.Background(), memberCfg, transport, router, auth,
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
		pool *cvPoolV2
		cert *cvPoolCertificateV2
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
	if err := cvVerifyPoolCertificateV2(&object.Pool, certificate, public.ControlSigner); err != nil {
		t.Fatal(err)
	}
	for range len(cfg.OldCommittee) - 1 {
		result := <-results
		if result.err != nil || !bytes.Equal(result.pool.Digest, object.Pool.Digest) ||
			cvVerifyPoolCertificateV2(result.pool, result.cert, public.ControlSigner) != nil {
			t.Fatalf("await certified V2 pool: %v", result.err)
		}
	}
	if got := transport.sentCount(cvTagPoolOfferV2); got < len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d offers", got)
	}
	if got := transport.sentCount(cvTagPoolCertShareV2); got < public.ControlSigner.Threshold()-1 {
		t.Fatalf("pool certification returned %d shares", got)
	}
	if got := transport.sentCount(cvTagPoolCertV2); got != len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d certificates", got)
	}
	offersAfterCertification := transport.sentCount(cvTagPoolOfferV2)
	certificatesAfterCertification := transport.sentCount(cvTagPoolCertV2)
	time.Sleep(2 * cvControlRetryIntervalV2)
	if got := transport.sentCount(cvTagPoolOfferV2); got != offersAfterCertification {
		t.Fatalf("pool offers continued after certification: before=%d after=%d", offersAfterCertification, got)
	}
	if got := transport.sentCount(cvTagPoolCertV2); got != certificatesAfterCertification {
		t.Fatalf("pool certificates continued after certification: before=%d after=%d", certificatesAfterCertification, got)
	}

	badCertificate := *certificate
	badCertificate.Certificate = append([]byte(nil), certificate.Certificate...)
	badCertificate.Certificate[0] ^= 1
	if _, err := services[cfg.OldCommittee[0]].ContributorCoin(ctx, &object.Pool, &badCertificate); err == nil {
		t.Fatal("released contributor coin share without a valid PoolCert")
	}
	type contributorResult struct {
		output *cvCoinOutputV2
		err    error
	}
	contributorResults := make(chan contributorResult, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		go func(node int) {
			output, coinErr := services[node].ContributorCoin(ctx, &object.Pool, certificate)
			contributorResults <- contributorResult{output: output, err: coinErr}
		}(member)
	}
	contributorInvocation, err := cvContributorCoinInvocationV2(public.ContextDigest, object.Pool.ProposerID, object.Pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var contributorValue []byte
	for range cfg.OldCommittee {
		result := <-contributorResults
		if result.err != nil || cvVerifyCoinOutputV2(result.output, contributorInvocation, public.CoinSigner) != nil {
			t.Fatalf("network contributor coin: %v", result.err)
		}
		if contributorValue == nil {
			contributorValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(contributorValue, result.output.Value) {
			t.Fatal("network contributor coin outputs differ")
		}
	}

	proposers, _, err := cvDeriveEligibilitySamplesV2(cfg.OldCommittee, public.EligibilityCoin.Value,
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
		nonEligiblePool, err := cvBuildPoolV2(public.ContextDigest, nonEligible, object.Pool.Components, public.Params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := services[nonEligible].CertifyPool(ctx, nonEligiblePool); err == nil {
			t.Fatal("certified a pool from a non-eligible proposer")
		}
	}
}

func TestCVAPDBNetworkServiceV2FinalizesDecisionAndRelaysHandoff(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	object, public := cvAgreementObjectV2Fixture(t)
	receiver := cfg.NewCommittee[0]
	localNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), receiver))
	transport := newCVRouterTestTransport(localNodes, 512)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, localNodes, 256, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	decisionRoot := t.TempDir()
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if node == receiver {
			localStore = nil
		} else {
			nodeCfg.DecisionStore, err = newCVDecisionSignStoreV2(decisionRoot)
			if err != nil {
				t.Fatal(err)
			}
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
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
			waitErr = cvVerifyHandoffV2(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
		}
		handoffResult <- waitErr
	}()
	finalized := make(chan error, len(cfg.OldCommittee))
	finalize := func(member int) {
		go func(node int) {
			handoff, finalizeErr := services[node].FinalizeDecision(ctx, object)
			if finalizeErr == nil {
				finalizeErr = cvVerifyHandoffV2(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
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
	if got := transport.sentCount(cvTagDecisionShareV2); got < len(cfg.OldCommittee)*(public.ControlSigner.Threshold()-1) {
		t.Fatalf("decision phase sent only %d shares", got)
	}
	minimumHandoffs := len(cfg.OldCommittee) + len(cfg.NewCommittee) - 1
	if got := transport.sentCount(cvTagHandoffV2); got < minimumHandoffs {
		t.Fatalf("decision phase sent only %d handoffs", got)
	}
}
