package core

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"
)

func TestCVCertifiedCandidateScalarAcceptsRelaysAndSuppressesDuplicates(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	_, _, receivers, cfg := cvNetworkAuthScalarFixture(t)
	auth, err := newCVNetworkAuthenticatorScalar(public.ValidatorKeys, receivers)
	if err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(cfg.OldCommittee, 256)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 128, auth,
	)
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
		services[member], err = newCVAPDBNetworkServiceScalar(
			context.Background(), memberCfg, transport, router, auth, holderStore,
			public.APDBSigner, public.ControlSigner, public.CoinSigner,
		)
		if err != nil {
			t.Fatal(err)
		}
		// The agreement fixture uses a synthetic context digest, so attach only
		// the public validator registry needed by the candidate predicate.
		services[member].cfg.Validators = public.ValidatorKeys
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	relay := cfg.OldCommittee[0]
	if relay == object.Header.ProposerID {
		relay = cfg.OldCommittee[1]
	}
	receiver := -1
	for _, member := range cfg.OldCommittee {
		if member != relay && member != object.Header.ProposerID {
			receiver = member
			break
		}
	}
	if receiver < 0 {
		t.Fatal("candidate retry test requires a non-origin receiver")
	}
	missingReceiver := -1
	for _, member := range cfg.OldCommittee {
		if member != relay && member != receiver && member != object.Header.ProposerID {
			missingReceiver = member
			break
		}
	}
	if missingReceiver < 0 {
		t.Fatal("candidate relay fallback test requires a fourth committee member")
	}
	// Exercise the retry path: loss of the first small ACK must trigger a
	// digest probe, not an immediate retransmission of the full candidate.
	transport.dropNext(receiver, relay, cvTagCertifiedCandidateACKScalar)
	// This target misses the publisher's first full object. A relay must probe,
	// observe no ACK, then fall back to a complete candidate transmission.
	transport.dropNext(relay, missingReceiver, cvTagCertifiedCandidateScalar)
	badObject := *object
	badObject.Header.ProposerID++
	badCtx, badCancel := context.WithTimeout(context.Background(), time.Second)
	if err := services[relay].PublishCertifiedCandidateScalar(badCtx, &badObject); err == nil {
		badCancel()
		t.Fatal("local candidate publisher accepted an unverified candidate")
	}
	badCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	published := make(chan error, 1)
	go func() { published <- services[relay].PublishCertifiedCandidateScalar(ctx, object) }()
	got, err := services[receiver].AwaitFirstCertifiedCandidateScalar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.ProposerID != object.Header.ProposerID || relay == object.Header.ProposerID {
		t.Fatalf("candidate relay=%d embedded proposer=%d", relay, got.Header.ProposerID)
	}
	missingGot, err := services[missingReceiver].AwaitFirstCertifiedCandidateScalar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if missingGot.Header.ProposerID != object.Header.ProposerID {
		t.Fatalf("relay fallback proposer=%d want=%d", missingGot.Header.ProposerID, object.Header.ProposerID)
	}
	if !cvCandidateProbeBeforeFullForTargetForTest(transport, missingReceiver, relay) {
		t.Fatal("missing receiver did not recover through relay probe-first full fallback")
	}

	proposers, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectScalarWireBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, accepted, err := services[receiver].acceptCertifiedCandidateScalar(wire); err != nil || accepted {
		t.Fatalf("duplicate candidate accepted=%v err=%v", accepted, err)
	}
	if !services[receiver].isVerifiedCertifiedCandidateScalar(wire) {
		t.Fatal("verified canonical candidate was not reusable by the agreement predicate")
	}
	cachedPublic, err := services[receiver].agreementPublicContextScalar()
	if err != nil {
		t.Fatal(err)
	}
	cachedProposers, cachedValidators, err := cvAgreementEligibilitySamplesScalar(cachedPublic)
	if err != nil || !equalInts(sortedIntsForTest(cachedProposers), sortedIntsForTest(proposers)) ||
		!equalInts(sortedIntsForTest(cachedValidators), sortedIntsForTest(validators)) {
		t.Fatalf("cached eligibility samples proposers=%v validators=%v err=%v", cachedProposers, cachedValidators, err)
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	if services[receiver].isVerifiedCertifiedCandidateScalar(mutated) {
		t.Fatal("mutated candidate matched the verified candidate cache")
	}
	if _, _, err := services[receiver].acceptCertifiedCandidateScalar(mutated); err == nil {
		t.Fatal("accepted mutated certified candidate")
	}
	ackCount := transport.sentCount(cvTagCertifiedCandidateACKScalar)
	services[receiver].handleCertifiedCandidateScalar(Message{
		From: relay, To: receiver, Tag: cvTagCertifiedCandidateScalar, Body: mutated,
	})
	ackDeadline := time.Now().Add(time.Second)
	for transport.sentCount(cvTagCertifiedCandidateACKScalar) <= ackCount && time.Now().Before(ackDeadline) {
		time.Sleep(time.Millisecond)
	}
	if transport.sentCount(cvTagCertifiedCandidateACKScalar) <= ackCount {
		t.Fatal("authenticated candidate delivery did not enqueue an ACK before validation")
	}
	select {
	case duplicate := <-services[receiver].certifiedCandidateChScalar:
		t.Fatalf("duplicate candidate reached first-candidate queue: proposer=%d", duplicate.Header.ProposerID)
	case <-time.After(20 * time.Millisecond):
	}

	deadline := time.Now().Add(time.Second)
	for !cvCandidateRelayAttemptedForTest(transport, receiver, relay) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cvCandidateRelayAttemptedForTest(transport, receiver, relay) {
		t.Fatalf("node %d accepted but did not relay candidate received from %d", receiver, relay)
	}
	// ACKs stop the per-peer retry loop. Allow relay workers to finish and
	// ensure no sender/receiver pair emits periodic duplicate full candidates.
	time.Sleep(150 * time.Millisecond)
	if transport.sentCount(cvTagCertifiedCandidateACKScalar) == 0 {
		t.Fatal("candidate delivery did not produce an authenticated ACK")
	}
	if countCVCandidateAfterACKForTest(transport, relay, receiver) != 0 {
		t.Fatalf("candidate publisher sent a full candidate after peer ACK")
	}
	if countCVCandidatePairForTest(transport, relay, receiver) > cvCandidateFanoutMaxAttemptsScalar {
		t.Fatalf("candidate publisher exceeded bounded retry budget")
	}
	if countCVTagPairForTest(transport, relay, receiver, cvTagCertifiedCandidateACKProbeScalar) == 0 {
		t.Fatalf("lost candidate ACK did not trigger a digest probe: full=%d ack=%d",
			countCVCandidatePairForTest(transport, relay, receiver),
			countCVTagPairForTest(transport, receiver, relay, cvTagCertifiedCandidateACKScalar))
	}
	if countCVCandidatePairForTest(transport, relay, receiver) != 1 {
		t.Fatalf("lost candidate ACK retransmitted full candidate before probe recovery")
	}
	cancel()
	if err := <-published; err != context.Canceled {
		t.Fatalf("candidate publisher shutdown error=%v", err)
	}
	if !bytes.Equal(got.Header.AggregateDigest, object.Header.AggregateDigest) {
		t.Fatal("relayed candidate changed aggregate digest")
	}
}

func sortedIntsForTest(values []int) []int {
	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	return copyValues
}

func TestCVCandidateFanoutACKSignalsArePerPeer(t *testing.T) {
	state := &cvCandidateFanoutStateScalar{
		acked: make(map[int]struct{}), waiters: make(map[int]chan struct{}),
	}
	first := state.ackedSignal(1)
	second := state.ackedSignal(2)
	state.markACK(1)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first peer ACK did not wake its waiter")
	}
	select {
	case <-second:
		t.Fatal("first peer ACK woke a different peer waiter")
	case <-time.After(20 * time.Millisecond):
	}
	state.markACK(2)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second peer ACK did not wake its waiter")
	}
}

func TestCVCandidateFanoutAttemptOrder(t *testing.T) {
	probe := []byte("probe")
	wire := []byte("candidate")
	for _, test := range []struct {
		name       string
		probeFirst bool
		want       []string
	}{
		{name: "origin-full-first", want: []string{
			cvTagCertifiedCandidateScalar, cvTagCertifiedCandidateACKProbeScalar,
			cvTagCertifiedCandidateScalar, cvTagCertifiedCandidateACKProbeScalar,
		}},
		{name: "relay-probe-first", probeFirst: true, want: []string{
			cvTagCertifiedCandidateACKProbeScalar, cvTagCertifiedCandidateScalar,
			cvTagCertifiedCandidateACKProbeScalar, cvTagCertifiedCandidateScalar,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for attempt, want := range test.want {
				tag, payload := cvCandidateFanoutAttemptScalar(attempt, test.probeFirst, probe, wire)
				if tag != want {
					t.Fatalf("attempt=%d tag=%s want=%s", attempt, tag, want)
				}
				wantPayload := wire
				if want == cvTagCertifiedCandidateACKProbeScalar {
					wantPayload = probe
				}
				if !bytes.Equal(payload, wantPayload) {
					t.Fatalf("attempt=%d payload=%q want=%q", attempt, payload, wantPayload)
				}
			}
		})
	}
}

func TestCVCandidateAnnounceIsBoundedByEligibleProposers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service := &cvAPDBNetworkServiceScalar{
		ctx:                             ctx,
		cfg:                             cvAPDBNetworkServiceConfigScalar{Params: cvScalarParams{proposerSampleSize: 1}},
		eligibleProposers:               map[int]struct{}{3: {}},
		candidateDigestByProposerScalar: make(map[int]string, 1),
		candidateOriginsScalar:          make(map[string]map[int]struct{}, 1),
		candidateFetchWaitersScalar:     make(map[string]map[int]struct{}, 1),
		certifiedCandidatesScalar:       make(map[string][]byte, 1),
		priorityOutbound:                make(chan cvOutboundMessageScalar, 4),
	}
	firstDigest := string(bytes.Repeat([]byte{1}, 32))
	secondDigest := string(bytes.Repeat([]byte{2}, 32))
	announce := func(origin int, digest string) Message {
		wire, err := cvEncodeCertifiedCandidateAnnounceScalar(origin, digest)
		if err != nil {
			t.Fatal(err)
		}
		return Message{From: origin, Body: wire}
	}

	service.handleCertifiedCandidateAnnounceScalar(announce(2, firstDigest))
	if len(service.candidateDigestByProposerScalar) != 0 || len(service.priorityOutbound) != 0 {
		t.Fatal("non-eligible proposer allocated candidate announce state")
	}
	service.handleCertifiedCandidateAnnounceScalar(announce(3, firstDigest))
	service.handleCertifiedCandidateAnnounceScalar(announce(3, firstDigest))
	service.handleCertifiedCandidateAnnounceScalar(announce(3, secondDigest))
	if got := service.candidateDigestByProposerScalar[3]; got != firstDigest {
		t.Fatal("eligible proposer candidate digest was replaced")
	}
	if len(service.candidateOriginsScalar) != 1 || len(service.priorityOutbound) != 1 {
		t.Fatalf("duplicate announces grew state: origins=%d fetches=%d", len(service.candidateOriginsScalar), len(service.priorityOutbound))
	}
	if origins := service.registerCandidateFetchWaiterScalar(secondDigest, 8); len(origins) != 0 || len(service.candidateFetchWaitersScalar) != 0 {
		t.Fatal("unknown candidate digest allocated fetch-waiter state")
	}
	if origins := service.registerCandidateFetchWaiterScalar(firstDigest, 8); len(origins) != 1 || origins[0] != 3 {
		t.Fatalf("known candidate fetch origins=%v", origins)
	}
}

func TestCVCandidateFanoutParallelScalesAndCaps(t *testing.T) {
	t.Setenv("RLADKR_CANDIDATE_FANOUT_PARALLEL", "")
	tests := []struct {
		peers int
		want  int
	}{
		{peers: 0, want: 0},
		{peers: 7, want: 7},
		{peers: 32, want: 16},
		{peers: 100, want: 24},
		{peers: 200, want: 32},
	}
	for _, test := range tests {
		if got := cvCandidateFanoutParallelScalar(test.peers); got != test.want {
			t.Fatalf("peers=%d parallel=%d want=%d", test.peers, got, test.want)
		}
	}
	t.Setenv("RLADKR_CANDIDATE_FANOUT_PARALLEL", "80")
	if got := cvCandidateFanoutParallelScalar(100); got != 64 {
		t.Fatalf("configured parallel=%d want=64", got)
	}
}

func TestCVCandidateFanoutPeersModes(t *testing.T) {
	roster := []int{7, 2, 5, 1, 4, 3, 6, 0}
	direct := cvCandidateFanoutPeersScalar(roster, 0, -1, 3, cvCandidateFanoutDirectOnlyScalar)
	if len(direct) != 7 {
		t.Fatalf("direct-only peers=%v", direct)
	}
	tree := cvCandidateFanoutPeersScalar(roster, 3, -1, 3, cvCandidateFanoutTreeScalar)
	if len(tree) != 2 || tree[0] != 4 || tree[1] != 5 {
		t.Fatalf("root tree children=%v", tree)
	}
	child := cvCandidateFanoutPeersScalar(roster, 4, -1, 3, cvCandidateFanoutTreeScalar)
	if len(child) != 2 || child[0] != 6 || child[1] != 7 {
		t.Fatalf("child tree children=%v", child)
	}
	if got := cvCandidateFanoutPeersScalar(roster, 3, 4, 3, cvCandidateFanoutTreeScalar); len(got) != 1 || got[0] != 5 {
		t.Fatalf("excluded tree child=%v", got)
	}
}

func TestCVCryptoQueueCapacityIsBounded(t *testing.T) {
	tests := []struct {
		committee int
		want      int
	}{
		{committee: 10, want: 64},
		{committee: 100, want: 200},
		{committee: 2000, want: 2048},
	}
	for _, test := range tests {
		if got := cvCryptoQueueCapacityScalar(test.committee); got != test.want {
			t.Fatalf("committee=%d capacity=%d want=%d", test.committee, got, test.want)
		}
	}
}

func TestCVCandidateFanoutMetricsDoNotCountCanceledWaitAsRetry(t *testing.T) {
	service := &cvAPDBNetworkServiceScalar{}
	service.recordCandidateFanoutAttemptScalar(3*time.Millisecond, false)
	service.recordCandidateFanoutAttemptScalar(5*time.Millisecond, true)
	metrics := service.experimentMetricsScalar()
	if metrics.candidateFanoutAttempts != 2 || metrics.candidateFanoutRetries != 1 {
		t.Fatalf("candidate attempts=%d retries=%d", metrics.candidateFanoutAttempts, metrics.candidateFanoutRetries)
	}
	if metrics.candidateFanoutACKWaitLatency != 8*time.Millisecond ||
		metrics.candidateFanoutRetryWaitLatency != 5*time.Millisecond {
		t.Fatalf("candidate ACK wait=%v retry wait=%v",
			metrics.candidateFanoutACKWaitLatency, metrics.candidateFanoutRetryWaitLatency)
	}
}

func TestCVCertifiedCandidateACKScalarCodec(t *testing.T) {
	digest := string(hashBytes([]byte("candidate-ack-test")))
	wire, err := cvEncodeCertifiedCandidateACKScalar(digest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cvDecodeCertifiedCandidateACKScalar(wire)
	if err != nil || got != digest {
		t.Fatalf("ACK round trip digest=%x err=%v", []byte(got), err)
	}
	for _, mutated := range [][]byte{
		wire[:len(wire)-1],
		append(append([]byte(nil), wire...), 0),
		append([]byte("wrong-domain"), wire[len(cvCertifiedCandidateACKScalarDomain):]...),
	} {
		if _, err := cvDecodeCertifiedCandidateACKScalar(mutated); err == nil {
			t.Fatal("malformed candidate ACK accepted")
		}
	}
}

func TestCVCandidateACKProbeRequiresDeliveredCandidate(t *testing.T) {
	digest := string(hashBytes([]byte("candidate-probe-delivery")))
	service := &cvAPDBNetworkServiceScalar{
		processingCandidatesScalar: make(map[string]struct{}),
		certifiedCandidatesScalar:  make(map[string][]byte),
	}
	if service.hasDeliveredCertifiedCandidateScalar(digest) {
		t.Fatal("unknown candidate digest counted as delivered")
	}
	service.processingCandidatesScalar[digest] = struct{}{}
	if !service.hasDeliveredCertifiedCandidateScalar(digest) {
		t.Fatal("candidate under verification not counted as delivered")
	}
	delete(service.processingCandidatesScalar, digest)
	service.certifiedCandidatesScalar[digest] = []byte("verified-wire")
	if !service.hasDeliveredCertifiedCandidateScalar(digest) {
		t.Fatal("verified candidate not counted as delivered")
	}
}

func TestCVCertifiedCandidatePullCodecs(t *testing.T) {
	digest := string(hashBytes([]byte("candidate-pull-test")))
	announce, err := cvEncodeCertifiedCandidateAnnounceScalar(7, digest)
	if err != nil {
		t.Fatal(err)
	}
	if origin, got, err := cvDecodeCertifiedCandidateAnnounceScalar(announce); err != nil || origin != 7 || got != digest {
		t.Fatalf("announce origin=%d digest=%x err=%v", origin, []byte(got), err)
	}
	request, err := cvEncodeCertifiedCandidateDigestRequestScalar(digest)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cvDecodeCertifiedCandidateDigestRequestScalar(request); err != nil || got != digest {
		t.Fatalf("request digest=%x err=%v", []byte(got), err)
	}
	candidate := []byte("candidate-wire")
	response, err := cvEncodeCertifiedCandidateResponseScalar(cvCertifiedCandidateDigestScalar(candidate), candidate)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, gotCandidate, err := cvDecodeCertifiedCandidateResponseScalar(response)
	if err != nil || gotDigest != cvCertifiedCandidateDigestScalar(candidate) || !bytes.Equal(gotCandidate, candidate) {
		t.Fatalf("response digest=%x candidate=%q err=%v", []byte(gotDigest), gotCandidate, err)
	}
	response[len(response)-1] ^= 1
	if _, _, err := cvDecodeCertifiedCandidateResponseScalar(response); err == nil {
		t.Fatal("mutated candidate response accepted")
	}
}

func cvCandidateRelayAttemptedForTest(transport *cvRouterTestTransport, from, excluded int) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, message := range transport.sent {
		if (message.Tag == cvTagCertifiedCandidateScalar || message.Tag == cvTagCertifiedCandidateACKProbeScalar) &&
			message.From == from && message.To != excluded {
			return true
		}
	}
	return false
}

func countCVCandidatePairForTest(transport *cvRouterTestTransport, from, to int) int {
	return countCVTagPairForTest(transport, from, to, cvTagCertifiedCandidateScalar)
}

func countCVTagPairForTest(transport *cvRouterTestTransport, from, to int, tag string) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	count := 0
	for _, message := range transport.sent {
		if message.Tag == tag && message.From == from && message.To == to {
			count++
		}
	}
	return count
}

func cvCandidateProbeBeforeFullForTargetForTest(transport *cvRouterTestTransport, to, publisher int) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	probeSeen := false
	for _, message := range transport.sent {
		if message.To != to || message.From == publisher {
			continue
		}
		switch message.Tag {
		case cvTagCertifiedCandidateACKProbeScalar:
			probeSeen = true
		case cvTagCertifiedCandidateScalar:
			return probeSeen
		}
	}
	return false
}

func countCVCandidateAfterACKForTest(transport *cvRouterTestTransport, from, to int) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	ackIndex := -1
	for index, message := range transport.sent {
		if message.Tag == cvTagCertifiedCandidateACKScalar && message.From == to && message.To == from {
			ackIndex = index
			break
		}
	}
	if ackIndex < 0 {
		return 0
	}
	count := 0
	for _, message := range transport.sent[ackIndex+1:] {
		if message.Tag == cvTagCertifiedCandidateScalar && message.From == from && message.To == to {
			count++
		}
	}
	return count
}
