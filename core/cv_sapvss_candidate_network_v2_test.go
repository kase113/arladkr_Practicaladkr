package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVCertifiedCandidateV2AcceptsRelaysAndSuppressesDuplicates(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, _, receivers, cfg := cvNetworkAuthV2Fixture(t)
	auth, err := newCVNetworkAuthenticatorV2(public.ValidatorKeys, receivers)
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
		services[member], err = newCVAPDBNetworkServiceV2(
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
	receiver := cfg.OldCommittee[len(cfg.OldCommittee)-1]
	if receiver == relay {
		receiver = cfg.OldCommittee[len(cfg.OldCommittee)-2]
	}
	badObject := *object
	badObject.Header.ProposerID++
	badCtx, badCancel := context.WithTimeout(context.Background(), time.Second)
	if err := services[relay].PublishCertifiedCandidateV2(badCtx, &badObject); err == nil {
		badCancel()
		t.Fatal("local candidate publisher accepted an unverified candidate")
	}
	badCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	published := make(chan error, 1)
	go func() { published <- services[relay].PublishCertifiedCandidateV2(ctx, object) }()
	got, err := services[receiver].AwaitFirstCertifiedCandidateV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.ProposerID != object.Header.ProposerID || relay == object.Header.ProposerID {
		t.Fatalf("candidate relay=%d embedded proposer=%d", relay, got.Header.ProposerID)
	}

	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, accepted, err := services[receiver].acceptCertifiedCandidateV2(wire); err != nil || accepted {
		t.Fatalf("duplicate candidate accepted=%v err=%v", accepted, err)
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	if _, _, err := services[receiver].acceptCertifiedCandidateV2(mutated); err == nil {
		t.Fatal("accepted mutated certified candidate")
	}
	ackCount := transport.sentCount(cvTagCertifiedCandidateACKV2)
	services[receiver].handleCertifiedCandidateV2(Message{
		From: relay, To: receiver, Tag: cvTagCertifiedCandidateV2, Body: mutated,
	})
	ackDeadline := time.Now().Add(time.Second)
	for transport.sentCount(cvTagCertifiedCandidateACKV2) <= ackCount && time.Now().Before(ackDeadline) {
		time.Sleep(time.Millisecond)
	}
	if transport.sentCount(cvTagCertifiedCandidateACKV2) <= ackCount {
		t.Fatal("authenticated candidate delivery did not enqueue an ACK before validation")
	}
	select {
	case duplicate := <-services[receiver].certifiedCandidateChV2:
		t.Fatalf("duplicate candidate reached first-candidate queue: proposer=%d", duplicate.Header.ProposerID)
	case <-time.After(20 * time.Millisecond):
	}

	deadline := time.Now().Add(time.Second)
	for !cvCandidateRelaySentForTest(transport, receiver, relay) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cvCandidateRelaySentForTest(transport, receiver, relay) {
		t.Fatalf("node %d accepted but did not relay candidate received from %d", receiver, relay)
	}
	// ACKs stop the per-peer retry loop. Allow relay workers to finish and
	// ensure no sender/receiver pair emits periodic duplicate full candidates.
	time.Sleep(150 * time.Millisecond)
	if transport.sentCount(cvTagCertifiedCandidateACKV2) == 0 {
		t.Fatal("candidate delivery did not produce an authenticated ACK")
	}
	if countCVCandidateAfterACKForTest(transport, relay, receiver) != 0 {
		t.Fatalf("candidate publisher sent a full candidate after peer ACK")
	}
	if countCVCandidatePairForTest(transport, relay, receiver) > cvCandidateFanoutMaxAttemptsV2 {
		t.Fatalf("candidate publisher exceeded bounded retry budget")
	}
	cancel()
	if err := <-published; err != context.Canceled {
		t.Fatalf("candidate publisher shutdown error=%v", err)
	}
	if !bytes.Equal(got.Header.AggregateDigest, object.Header.AggregateDigest) {
		t.Fatal("relayed candidate changed aggregate digest")
	}
}

func TestCVCandidateFanoutACKSignalsArePerPeer(t *testing.T) {
	state := &cvCandidateFanoutStateV2{
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
		if got := cvCandidateFanoutParallelV2(test.peers); got != test.want {
			t.Fatalf("peers=%d parallel=%d want=%d", test.peers, got, test.want)
		}
	}
	t.Setenv("RLADKR_CANDIDATE_FANOUT_PARALLEL", "80")
	if got := cvCandidateFanoutParallelV2(100); got != 64 {
		t.Fatalf("configured parallel=%d want=64", got)
	}
}

func TestCVCandidateFanoutPeersModes(t *testing.T) {
	roster := []int{7, 2, 5, 1, 4, 3, 6, 0}
	direct := cvCandidateFanoutPeersV2(roster, 0, -1, 3, cvCandidateFanoutDirectOnlyV2)
	if len(direct) != 7 {
		t.Fatalf("direct-only peers=%v", direct)
	}
	tree := cvCandidateFanoutPeersV2(roster, 3, -1, 3, cvCandidateFanoutTreeV2)
	if len(tree) != 2 || tree[0] != 4 || tree[1] != 5 {
		t.Fatalf("root tree children=%v", tree)
	}
	child := cvCandidateFanoutPeersV2(roster, 4, -1, 3, cvCandidateFanoutTreeV2)
	if len(child) != 2 || child[0] != 6 || child[1] != 7 {
		t.Fatalf("child tree children=%v", child)
	}
	if got := cvCandidateFanoutPeersV2(roster, 3, 4, 3, cvCandidateFanoutTreeV2); len(got) != 1 || got[0] != 5 {
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
		if got := cvCryptoQueueCapacityV2(test.committee); got != test.want {
			t.Fatalf("committee=%d capacity=%d want=%d", test.committee, got, test.want)
		}
	}
}

func TestCVCandidateFanoutMetricsDoNotCountCanceledWaitAsRetry(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{}
	service.recordCandidateFanoutAttemptV2(3*time.Millisecond, false)
	service.recordCandidateFanoutAttemptV2(5*time.Millisecond, true)
	metrics := service.experimentMetricsV2()
	if metrics.candidateFanoutAttempts != 2 || metrics.candidateFanoutRetries != 1 {
		t.Fatalf("candidate attempts=%d retries=%d", metrics.candidateFanoutAttempts, metrics.candidateFanoutRetries)
	}
	if metrics.candidateFanoutACKWaitLatency != 8*time.Millisecond ||
		metrics.candidateFanoutRetryWaitLatency != 5*time.Millisecond {
		t.Fatalf("candidate ACK wait=%v retry wait=%v",
			metrics.candidateFanoutACKWaitLatency, metrics.candidateFanoutRetryWaitLatency)
	}
}

func TestCVCertifiedCandidateACKV2Codec(t *testing.T) {
	digest := string(hashBytes([]byte("candidate-ack-test")))
	wire, err := cvEncodeCertifiedCandidateACKV2(digest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cvDecodeCertifiedCandidateACKV2(wire)
	if err != nil || got != digest {
		t.Fatalf("ACK round trip digest=%x err=%v", []byte(got), err)
	}
	for _, mutated := range [][]byte{
		wire[:len(wire)-1],
		append(append([]byte(nil), wire...), 0),
		append([]byte("wrong-domain"), wire[len(cvCertifiedCandidateACKV2Domain):]...),
	} {
		if _, err := cvDecodeCertifiedCandidateACKV2(mutated); err == nil {
			t.Fatal("malformed candidate ACK accepted")
		}
	}
}

func TestCVCertifiedCandidatePullCodecs(t *testing.T) {
	digest := string(hashBytes([]byte("candidate-pull-test")))
	announce, err := cvEncodeCertifiedCandidateAnnounceV2(7, digest)
	if err != nil {
		t.Fatal(err)
	}
	if origin, got, err := cvDecodeCertifiedCandidateAnnounceV2(announce); err != nil || origin != 7 || got != digest {
		t.Fatalf("announce origin=%d digest=%x err=%v", origin, []byte(got), err)
	}
	request, err := cvEncodeCertifiedCandidateDigestRequestV2(digest)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cvDecodeCertifiedCandidateDigestRequestV2(request); err != nil || got != digest {
		t.Fatalf("request digest=%x err=%v", []byte(got), err)
	}
	candidate := []byte("candidate-wire")
	response, err := cvEncodeCertifiedCandidateResponseV2(cvCertifiedCandidateDigestV2(candidate), candidate)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, gotCandidate, err := cvDecodeCertifiedCandidateResponseV2(response)
	if err != nil || gotDigest != cvCertifiedCandidateDigestV2(candidate) || !bytes.Equal(gotCandidate, candidate) {
		t.Fatalf("response digest=%x candidate=%q err=%v", []byte(gotDigest), gotCandidate, err)
	}
	response[len(response)-1] ^= 1
	if _, _, err := cvDecodeCertifiedCandidateResponseV2(response); err == nil {
		t.Fatal("mutated candidate response accepted")
	}
}

func cvCandidateRelaySentForTest(transport *cvRouterTestTransport, from, excluded int) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, message := range transport.sent {
		if message.Tag == cvTagCertifiedCandidateV2 && message.From == from && message.To != excluded {
			return true
		}
	}
	return false
}

func countCVCandidatePairForTest(transport *cvRouterTestTransport, from, to int) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	count := 0
	for _, message := range transport.sent {
		if message.Tag == cvTagCertifiedCandidateV2 && message.From == from && message.To == to {
			count++
		}
	}
	return count
}

func countCVCandidateAfterACKForTest(transport *cvRouterTestTransport, from, to int) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	ackIndex := -1
	for index, message := range transport.sent {
		if message.Tag == cvTagCertifiedCandidateACKV2 && message.From == to && message.To == from {
			ackIndex = index
			break
		}
	}
	if ackIndex < 0 {
		return 0
	}
	count := 0
	for _, message := range transport.sent[ackIndex+1:] {
		if message.Tag == cvTagCertifiedCandidateV2 && message.From == from && message.To == to {
			count++
		}
	}
	return count
}
