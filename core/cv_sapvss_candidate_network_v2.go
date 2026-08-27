package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cvCertifiedCandidateDigestV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/certified-candidate-digest"

const (
	cvCertifiedCandidateACKV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/certified-candidate-ack"
	cvCandidateFanoutMaxAttemptsV2  = 4
	cvCandidateFanoutRetryBaseV2    = 250 * time.Millisecond
)

const (
	cvCandidateFanoutFloodV2         = "flood"
	cvCandidateFanoutDirectOnlyV2    = "direct-only"
	cvCandidateFanoutTreeV2          = "tree"
	cvCandidateFanoutPullV2          = "pull"
	cvCandidateFanoutValidatorPullV2 = "validator-pull"
)

func cvCandidateFanoutModeV2() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_CANDIDATE_FANOUT_MODE")))
	if mode == cvCandidateFanoutDirectOnlyV2 || mode == cvCandidateFanoutTreeV2 || mode == cvCandidateFanoutPullV2 || mode == cvCandidateFanoutValidatorPullV2 {
		return mode
	}
	return cvCandidateFanoutFloodV2
}

const (
	cvCertifiedCandidateAnnounceDomainV2 = "ARL-CV-sAPVSS/v2/candidate-announce"
	cvCertifiedCandidateFetchDomainV2    = "ARL-CV-sAPVSS/v2/candidate-fetch"
	cvCertifiedCandidateResponseDomainV2 = "ARL-CV-sAPVSS/v2/candidate-response"
)

func cvEncodeCertifiedCandidateAnnounceV2(origin int, digest string) ([]byte, error) {
	if origin < 0 || len(digest) != 32 {
		return nil, fmt.Errorf("invalid candidate announce")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateAnnounceDomainV2))
	cvWriteUint64(&wire, uint64(origin))
	_ = cvWriteBytes(&wire, []byte(digest))
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateAnnounceV2(wire []byte) (int, string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateAnnounceDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateAnnounceDomainV2)) {
		return 0, "", fmt.Errorf("invalid candidate announce domain")
	}
	origin, err := r.uint64()
	if err != nil || origin > uint64(^uint(0)>>1) {
		return 0, "", fmt.Errorf("invalid candidate announce origin")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return 0, "", fmt.Errorf("invalid candidate announce digest")
	}
	return int(origin), string(digest), nil
}

func cvEncodeCertifiedCandidateDigestRequestV2(digest string) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid candidate fetch digest")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateFetchDomainV2))
	_ = cvWriteBytes(&wire, []byte(digest))
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateDigestRequestV2(wire []byte) (string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateFetchDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateFetchDomainV2)) {
		return "", fmt.Errorf("invalid candidate fetch domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return "", fmt.Errorf("invalid candidate fetch digest")
	}
	return string(digest), nil
}

func cvEncodeCertifiedCandidateResponseV2(digest string, candidate []byte) ([]byte, error) {
	if len(digest) != 32 || len(candidate) == 0 {
		return nil, fmt.Errorf("invalid candidate response")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateResponseDomainV2))
	_ = cvWriteBytes(&wire, []byte(digest))
	_ = cvWriteBytes(&wire, candidate)
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateResponseV2(wire []byte) (string, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateResponseDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateResponseDomainV2)) {
		return "", nil, fmt.Errorf("invalid candidate response domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return "", nil, fmt.Errorf("invalid candidate response digest")
	}
	candidate, err := r.bytes(cvMaxAgreementObjectV2Bytes)
	if err != nil || len(candidate) == 0 || r.reader.Len() != 0 {
		return "", nil, fmt.Errorf("invalid candidate response payload")
	}
	if cvCertifiedCandidateDigestV2(candidate) != string(digest) {
		return "", nil, fmt.Errorf("candidate response digest mismatch")
	}
	return string(digest), candidate, nil
}

func cvCandidateFanoutParallelV2(peers int) int {
	if peers <= 0 {
		return 0
	}
	parallel := 8
	switch {
	case peers > 128:
		parallel = 32
	case peers > 64:
		parallel = 24
	case peers > 16:
		parallel = 16
	}
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_CANDIDATE_FANOUT_PARALLEL"))); err == nil && configured > 0 {
		parallel = configured
	}
	if parallel > 64 {
		parallel = 64
	}
	if parallel > peers {
		parallel = peers
	}
	return parallel
}

type cvCandidateResponseCallV2 struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvCandidateFanoutStateV2 struct {
	mu       sync.Mutex
	acked    map[int]struct{}
	waiters  map[int]chan struct{}
	ackProbe []byte
	refs     int
}

func (s *cvCandidateFanoutStateV2) markACK(peer int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.acked == nil {
		s.acked = make(map[int]struct{})
	}
	if _, duplicate := s.acked[peer]; duplicate {
		s.mu.Unlock()
		return
	}
	s.acked[peer] = struct{}{}
	if waiter := s.waiters[peer]; waiter != nil {
		close(waiter)
	}
	s.mu.Unlock()
}

func (s *cvCandidateFanoutStateV2) isACKed(peer int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	_, ok := s.acked[peer]
	s.mu.Unlock()
	return ok
}

func (s *cvCandidateFanoutStateV2) ackedSignal(peer int) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters == nil {
		s.waiters = make(map[int]chan struct{})
	}
	if waiter := s.waiters[peer]; waiter != nil {
		return waiter
	}
	waiter := make(chan struct{})
	s.waiters[peer] = waiter
	if _, ok := s.acked[peer]; ok {
		close(waiter)
	}
	return waiter
}

func cvCertifiedCandidateDigestV2(wire []byte) string {
	return string(hashBytes([]byte(cvCertifiedCandidateDigestV2Domain), wire))
}

func cvEncodeCertifiedCandidateACKV2(digest string) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 certified candidate ACK digest")
	}
	wire := make([]byte, len(cvCertifiedCandidateACKV2Domain)+len(digest))
	copy(wire, []byte(cvCertifiedCandidateACKV2Domain))
	copy(wire[len(cvCertifiedCandidateACKV2Domain):], []byte(digest))
	return wire, nil
}

func cvDecodeCertifiedCandidateACKV2(wire []byte) (string, error) {
	domain := []byte(cvCertifiedCandidateACKV2Domain)
	if len(wire) != len(domain)+32 || !bytes.Equal(wire[:len(domain)], domain) {
		return "", fmt.Errorf("invalid CV V2 certified candidate ACK")
	}
	return string(wire[len(domain):]), nil
}

func (s *cvAPDBNetworkServiceV2) candidateFanoutStateV2(digest string) *cvCandidateFanoutStateV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidateFanoutV2 == nil {
		s.candidateFanoutV2 = make(map[string]*cvCandidateFanoutStateV2)
	}
	state := s.candidateFanoutV2[digest]
	if state == nil {
		probe, _ := cvEncodeCertifiedCandidateACKV2(digest)
		state = &cvCandidateFanoutStateV2{
			acked: make(map[int]struct{}), waiters: make(map[int]chan struct{}), ackProbe: probe,
		}
		s.candidateFanoutV2[digest] = state
	}
	state.refs++
	return state
}

func (s *cvAPDBNetworkServiceV2) releaseCandidateFanoutStateV2(digest string, state *cvCandidateFanoutStateV2) {
	if s == nil || state == nil {
		return
	}
	s.mu.Lock()
	if current := s.candidateFanoutV2[digest]; current == state {
		state.refs--
		if state.refs <= 0 {
			delete(s.candidateFanoutV2, digest)
		}
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) markCertifiedCandidateACKV2(digest string, peer int) {
	if s == nil || len(digest) != 32 {
		return
	}
	s.mu.Lock()
	state := s.candidateFanoutV2[digest]
	s.mu.Unlock()
	if state != nil {
		state.markACK(peer)
	}
}

func (s *cvAPDBNetworkServiceV2) cachedCertifiedCandidateWireV2(digest string) []byte {
	if s == nil || digest == "" {
		return nil
	}
	s.mu.Lock()
	wire := append([]byte(nil), s.certifiedCandidatesV2[digest]...)
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceV2) waitCertifiedCandidateACKV2(
	ctx context.Context, state *cvCandidateFanoutStateV2, peer int, delay time.Duration,
) bool {
	if state == nil || state.isACKed(peer) {
		return state != nil
	}
	acked := state.ackedSignal(peer)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-s.ctx.Done():
		return false
	case <-acked:
		return true
	case <-timer.C:
		return state.isACKed(peer)
	}
}

func (s *cvAPDBNetworkServiceV2) sendCertifiedCandidatePeerV2(
	ctx context.Context, state *cvCandidateFanoutStateV2, peer int, digest string, wire []byte, probeFirst bool,
) error {
	started := time.Now()
	defer func() { s.recordCandidateFanoutPeerLatencyV2(time.Since(started)) }()
	// ackProbe is immutable for this digest and safe for concurrent readers.
	probe := state.ackProbe
	if len(probe) == 0 {
		var err error
		probe, err = cvEncodeCertifiedCandidateACKV2(digest)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < cvCandidateFanoutMaxAttemptsV2; attempt++ {
		if state.isACKed(peer) {
			return nil
		}
		delay := cvCandidateFanoutRetryBaseV2 << attempt
		tag, payload := cvCandidateFanoutAttemptV2(attempt, probeFirst, probe, wire)
		if tag == cvTagCertifiedCandidateACKProbeV2 {
			// A successful first delivery may have lost only its small ACK. Probe
			// the receiver's delivered/verified state before transmitting the
			// complete candidate on the next attempt. Relays start with this probe
			// because the origin has already flooded the same canonical object.
		}
		if err := s.send(peer, tag, payload); err == nil {
			waitStarted := time.Now()
			acknowledged := s.waitCertifiedCandidateACKV2(ctx, state, peer, delay)
			canceled := ctx.Err() != nil || s.ctx.Err() != nil
			s.recordCandidateFanoutAttemptV2(time.Since(waitStarted), !acknowledged && !canceled)
			if acknowledged {
				return nil
			}
			if canceled {
				if err := ctx.Err(); err != nil {
					return err
				}
				return s.ctx.Err()
			}
		} else if ctx.Err() != nil || s.ctx.Err() != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return s.ctx.Err()
		} else {
			// A failed send cannot produce an ACK for this attempt. Preserve the
			// exponential retry pacing, but avoid waiting on an impossible ACK.
			waitStarted := time.Now()
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-s.ctx.Done():
				timer.Stop()
				return s.ctx.Err()
			case <-timer.C:
			}
			s.recordCandidateFanoutAttemptV2(time.Since(waitStarted), true)
		}
	}
	if state.isACKed(peer) {
		return nil
	}
	return fmt.Errorf("CV V2 candidate ACK timeout from peer %d for %x", peer, []byte(digest))
}

func cvCandidateFanoutAttemptV2(attempt int, probeFirst bool, probe, wire []byte) (string, []byte) {
	probeAttempt := attempt%2 == 1
	if probeFirst {
		probeAttempt = attempt%2 == 0
	}
	if probeAttempt {
		return cvTagCertifiedCandidateACKProbeV2, probe
	}
	return cvTagCertifiedCandidateV2, wire
}

// fanoutCandidateV2 sends one canonical candidate to each peer with bounded
// parallelism. A peer is retried only until it ACKs or the bounded attempt
// budget is exhausted; successful peers are never included in later retries.
func (s *cvAPDBNetworkServiceV2) fanoutCandidateV2(
	ctx context.Context, digest string, wire []byte, excluded, origin int, probeFirst bool,
) error {
	if s == nil || ctx == nil || len(digest) != 32 || len(wire) == 0 {
		return fmt.Errorf("invalid CV V2 candidate fanout")
	}
	mode := cvCandidateFanoutModeV2()
	if mode == cvCandidateFanoutPullV2 || mode == cvCandidateFanoutValidatorPullV2 {
		if mode == cvCandidateFanoutValidatorPullV2 {
			if _, validators, sampleErr := cvAgreementEligibilitySamplesV2Must(s); sampleErr == nil {
				// Prefetch the complete authenticated candidate into every validator
				// before announcing the digest. Validators then form a recovery set
				// if the proposer disappears after publication.
				for _, validator := range validators {
					if validator != s.cfg.LocalNode {
						if err := s.send(validator, cvTagCertifiedCandidateV2, wire); err != nil {
							return err
						}
					}
				}
			}
		}
		announce, err := cvEncodeCertifiedCandidateAnnounceV2(origin, digest)
		if err != nil {
			return err
		}
		for _, peer := range cvCandidateFanoutPeersV2(s.cfg.OldRoster, s.cfg.LocalNode, excluded, origin, cvCandidateFanoutDirectOnlyV2) {
			if err := s.send(peer, cvTagCertifiedCandidateAnnounceV2, announce); err != nil {
				return err
			}
		}
		return nil
	}
	peers := cvCandidateFanoutPeersV2(s.cfg.OldRoster, s.cfg.LocalNode, excluded, origin, mode)
	if len(peers) == 0 {
		return nil
	}
	state := s.candidateFanoutStateV2(digest)
	defer s.releaseCandidateFanoutStateV2(digest, state)
	parallel := cvCandidateFanoutParallelV2(len(peers))
	sem := make(chan struct{}, parallel)
	errs := make(chan error, len(peers))
	var workers sync.WaitGroup
	for _, peer := range peers {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
		peer := peer
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-sem }()
			errs <- s.sendCertifiedCandidatePeerV2(ctx, state, peer, digest, wire, probeFirst)
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func cvCandidateFanoutPeersV2(roster []int, local, excluded, origin int, mode string) []int {
	ordered := append([]int(nil), roster...)
	sort.Ints(ordered)
	if mode != cvCandidateFanoutTreeV2 {
		peers := make([]int, 0, len(ordered))
		for _, member := range ordered {
			if member != local && member != excluded {
				peers = append(peers, member)
			}
		}
		return peers
	}
	root := sort.SearchInts(ordered, origin)
	if root >= len(ordered) || ordered[root] != origin {
		return nil
	}
	rotated := append(append([]int(nil), ordered[root:]...), ordered[:root]...)
	localIndex := -1
	for i, member := range rotated {
		if member == local {
			localIndex = i
			break
		}
	}
	if localIndex < 0 {
		return nil
	}
	peers := make([]int, 0, 2)
	for _, child := range []int{2*localIndex + 1, 2*localIndex + 2} {
		if child < len(rotated) && rotated[child] != excluded {
			peers = append(peers, rotated[child])
		}
	}
	return peers
}

func (s *cvAPDBNetworkServiceV2) agreementPublicContextV2() (cvAgreementPublicContextV2, error) {
	if s == nil {
		return cvAgreementPublicContextV2{}, fmt.Errorf("nil CV V2 candidate service")
	}
	s.mu.Lock()
	if cached := s.agreementPublicContextCache; cached != nil {
		public := *cached
		s.mu.Unlock()
		return public, nil
	}
	coin := s.eligibilityCoin
	proposers := append([]int(nil), s.eligibleProposerSample...)
	if len(proposers) == 0 {
		proposers = make([]int, 0, len(s.eligibleProposers))
		for proposer := range s.eligibleProposers {
			proposers = append(proposers, proposer)
		}
		sort.Ints(proposers)
	}
	validators := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	if coin == nil {
		return cvAgreementPublicContextV2{}, fmt.Errorf("CV V2 eligibility coin is not available")
	}
	public := cvAgreementPublicContextV2{
		SID: s.cfg.SID, Epoch: s.cfg.Epoch, ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...),
		OldCommittee: append([]int(nil), s.cfg.OldRoster...), EligibilityCoin: coin, Params: s.cfg.Params,
		APDBSigner: s.apdbSigner, ControlSigner: s.controlSigner, CoinSigner: s.coinSigner,
		ValidatorKeys: s.cfg.Validators, verifiedProposerSample: proposers,
		verifiedValidatorSample: validators, eligibilityVerified: true,
		verifiedCandidate: s.isVerifiedCertifiedCandidateV2,
	}
	if _, _, err := cvAgreementEligibilitySamplesV2(public); err != nil {
		return cvAgreementPublicContextV2{}, err
	}
	s.mu.Lock()
	if s.agreementPublicContextCache == nil {
		cached := public
		s.agreementPublicContextCache = &cached
	} else {
		public = *s.agreementPublicContextCache
	}
	s.mu.Unlock()
	return public, nil
}

func (s *cvAPDBNetworkServiceV2) isVerifiedCertifiedCandidateV2(wire []byte) bool {
	if s == nil || len(wire) == 0 {
		return false
	}
	digest := cvCertifiedCandidateDigestV2(wire)
	s.mu.Lock()
	cached := s.certifiedCandidatesV2[digest]
	s.mu.Unlock()
	return bytes.Equal(cached, wire)
}

func (s *cvAPDBNetworkServiceV2) acceptCertifiedCandidateV2(wire []byte) (*cvAgreementObjectV2, bool, error) {
	digest := cvCertifiedCandidateDigestV2(wire)
	return s.acceptCertifiedCandidateDigestV2(wire, digest)
}

func (s *cvAPDBNetworkServiceV2) acceptCertifiedCandidateDigestV2(
	wire []byte, digest string,
) (*cvAgreementObjectV2, bool, error) {
	if digest == "" {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate digest")
	}
	s.mu.Lock()
	cached := s.certifiedCandidatesV2[digest]
	s.mu.Unlock()
	if len(cached) != 0 {
		if bytes.Equal(cached, wire) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("conflicting CV V2 certified candidate digest")
	}
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return nil, false, err
	}
	// agreementPublicContextV2 validates and snapshots the eligibility samples;
	// reuse that immutable snapshot instead of repeating the same checks.
	validators := append([]int(nil), public.verifiedValidatorSample...)
	object, err := cvDecodeAgreementObjectV2(wire, s.cfg.Params, validators)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate")
	}
	canonical, err := cvValidateAgreementObjectV2(object, public)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate")
	}
	// Normalize the cached representation to the locally selected wire mode.
	// The transport digest remains tied to the actual wire bytes, preserving
	// authenticated fetch semantics during a rolling deployment.
	if !bytes.Equal(canonical, wire) {
		digest = cvCertifiedCandidateDigestV2(canonical)
	}
	return s.rememberVerifiedCertifiedCandidateV2(object, digest, canonical)
}

// rememberVerifiedCertifiedCandidateV2 is only for an object that was
// canonicalized and fully verified immediately before this call. Network
// input must use acceptCertifiedCandidateV2 so the provenance cannot be
// forged by an untrusted wire payload.
func (s *cvAPDBNetworkServiceV2) rememberVerifiedCertifiedCandidateV2(
	object *cvAgreementObjectV2, digest string, canonical []byte,
) (*cvAgreementObjectV2, bool, error) {
	if object == nil || digest == "" || len(canonical) == 0 {
		return nil, false, fmt.Errorf("invalid verified CV V2 certified candidate")
	}
	s.mu.Lock()
	if existingDigest := s.candidateDigestByProposerV2[object.Header.ProposerID]; existingDigest != "" && existingDigest != digest {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("conflicting CV V2 candidate for proposer")
	}
	if existing := s.certifiedCandidatesV2[digest]; len(existing) != 0 {
		s.mu.Unlock()
		if bytes.Equal(existing, canonical) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("conflicting CV V2 certified candidate digest")
	}
	s.candidateDigestByProposerV2[object.Header.ProposerID] = digest
	s.certifiedCandidatesV2[digest] = append([]byte(nil), canonical...)
	s.mu.Unlock()
	select {
	case s.certifiedCandidateChV2 <- object:
	case <-s.ctx.Done():
		return nil, false, s.ctx.Err()
	}
	return object, true, nil
}

func (s *cvAPDBNetworkServiceV2) registerCandidateOriginV2(origin int, digest string) bool {
	if s == nil || origin < 0 || len(digest) != 32 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, eligible := s.eligibleProposers[origin]; !eligible {
		return false
	}
	if _, exists := s.candidateDigestByProposerV2[origin]; exists {
		return false
	}
	if len(s.candidateDigestByProposerV2) >= s.cfg.Params.proposerSampleSize {
		return false
	}
	s.candidateDigestByProposerV2[origin] = digest
	if s.candidateOriginsV2[digest] == nil {
		s.candidateOriginsV2[digest] = make(map[int]struct{}, 1)
	}
	s.candidateOriginsV2[digest][origin] = struct{}{}
	return true
}

func (s *cvAPDBNetworkServiceV2) acceptVerifiedCertifiedCandidateV2(
	object *cvAgreementObjectV2, canonical []byte,
) (*cvAgreementObjectV2, bool, error) {
	if object == nil || len(canonical) == 0 {
		return nil, false, fmt.Errorf("invalid verified CV V2 certified candidate")
	}
	digest := cvCertifiedCandidateDigestV2(canonical)
	return s.rememberVerifiedCertifiedCandidateV2(object, digest, canonical)
}

func (s *cvAPDBNetworkServiceV2) PublishCertifiedCandidateV2(
	ctx context.Context, candidate *cvAgreementObjectV2,
) error {
	if s == nil || ctx == nil || candidate == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return fmt.Errorf("invalid CV V2 certified candidate publisher")
	}
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return err
	}
	wire, err := cvValidateAgreementObjectV2(candidate, public)
	if err != nil {
		return fmt.Errorf("invalid local CV V2 certified candidate")
	}
	if _, _, err := s.acceptVerifiedCertifiedCandidateV2(candidate, wire); err != nil {
		return err
	}
	digest := cvCertifiedCandidateDigestV2(wire)
	if cached := s.cachedCertifiedCandidateWireV2(digest); len(cached) != 0 {
		wire = cached
	}
	if err := s.fanoutCandidateV2(ctx, digest, wire, -1, candidate.Header.ProposerID, false); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}

// publishLocallyCertifiedCandidateV2 is restricted to the proposer pipeline,
// after CertifyAggregate has validated the Pool, contributor coin, ARC and
// recovered VCert. Network-originated candidates must use the full verifier.
func (s *cvAPDBNetworkServiceV2) publishLocallyCertifiedCandidateV2(
	ctx context.Context, candidate *cvAgreementObjectV2,
) error {
	if s == nil || ctx == nil || candidate == nil || candidate.Header.ProposerID != s.cfg.LocalNode {
		return fmt.Errorf("invalid locally certified CV V2 candidate")
	}
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return err
	}
	// The context constructor already validated the cached sample.
	validators := append([]int(nil), public.verifiedValidatorSample...)
	wire, err := cvAgreementObjectV2WireBytes(candidate, s.cfg.Params, validators)
	if err != nil {
		return err
	}
	if _, _, err := s.acceptVerifiedCertifiedCandidateV2(candidate, wire); err != nil {
		return err
	}
	digest := cvCertifiedCandidateDigestV2(wire)
	if err := s.fanoutCandidateV2(ctx, digest, wire, -1, candidate.Header.ProposerID, false); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *cvAPDBNetworkServiceV2) AwaitFirstCertifiedCandidateV2(
	ctx context.Context,
) (*cvAgreementObjectV2, error) {
	if s == nil || ctx == nil {
		return nil, fmt.Errorf("invalid CV V2 certified candidate wait")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case candidate := <-s.certifiedCandidateChV2:
		return candidate, nil
	}
}

func (s *cvAPDBNetworkServiceV2) CertifiedCandidateCountV2() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certifiedCandidatesV2)
}

func (s *cvAPDBNetworkServiceV2) acknowledgeCertifiedCandidateV2(msg Message) string {
	digest := cvCertifiedCandidateDigestV2(msg.Body)
	s.acknowledgeCertifiedCandidateDigestV2(msg, digest)
	return digest
}

func (s *cvAPDBNetworkServiceV2) acknowledgeCertifiedCandidateDigestV2(msg Message, digest string) {
	// This ACK confirms delivery of an authenticated envelope, not candidate
	// validity. Sending it before expensive verification avoids WAN retries
	// while preserving the verification gate below.
	if ack := s.cachedCandidateACKWireV2(digest); len(ack) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagCertifiedCandidateACKV2, ack, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) cachedCandidateACKWireV2(digest string) []byte {
	if s == nil || len(digest) != 32 {
		return nil
	}
	s.mu.Lock()
	if wire := s.candidateACKWiresV2[digest]; len(wire) != 0 {
		s.mu.Unlock()
		return wire
	}
	wire, err := cvEncodeCertifiedCandidateACKV2(digest)
	if err == nil {
		if s.candidateACKWiresV2 == nil {
			s.candidateACKWiresV2 = make(map[string][]byte)
		}
		s.candidateACKWiresV2[digest] = wire
	}
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceV2) cachedCandidateResponseWireV2(digest string, candidate []byte) []byte {
	if s == nil || len(digest) != 32 || len(candidate) == 0 {
		return nil
	}
	s.mu.Lock()
	if wire := s.candidateResponseWiresV2[digest]; len(wire) != 0 {
		s.mu.Unlock()
		return wire
	}
	if call := s.candidateResponseCallsV2[digest]; call != nil {
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
			return nil
		case <-call.ready:
			return call.response
		}
	}
	call := &cvCandidateResponseCallV2{ready: make(chan struct{})}
	if s.candidateResponseCallsV2 == nil {
		s.candidateResponseCallsV2 = make(map[string]*cvCandidateResponseCallV2)
	}
	s.candidateResponseCallsV2[digest] = call
	s.mu.Unlock()
	wire, err := cvEncodeCertifiedCandidateResponseV2(digest, candidate)
	s.mu.Lock()
	if err == nil {
		if s.candidateResponseWiresV2 == nil {
			s.candidateResponseWiresV2 = make(map[string][]byte)
		}
		s.candidateResponseWiresV2[digest] = wire
	}
	call.response = wire
	call.err = err
	delete(s.candidateResponseCallsV2, digest)
	close(call.ready)
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateACKProbeV2(msg Message) {
	digest, err := cvDecodeCertifiedCandidateACKV2(msg.Body)
	if err != nil || !s.hasDeliveredCertifiedCandidateV2(digest) {
		return
	}
	if ack := s.cachedCandidateACKWireV2(digest); len(ack) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagCertifiedCandidateACKV2, ack, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) hasDeliveredCertifiedCandidateV2(digest string) bool {
	if s == nil || len(digest) != 32 {
		return false
	}
	s.mu.Lock()
	_, processing := s.processingCandidatesV2[digest]
	delivered := processing || len(s.certifiedCandidatesV2[digest]) != 0
	s.mu.Unlock()
	return delivered
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateAnnounceV2(msg Message) {
	origin, digest, err := cvDecodeCertifiedCandidateAnnounceV2(msg.Body)
	if err != nil || origin != msg.From || len(s.cachedCertifiedCandidateWireV2(digest)) != 0 {
		return
	}
	if !s.registerCandidateOriginV2(origin, digest) {
		return
	}
	if cvCandidateFanoutModeV2() == cvCandidateFanoutValidatorPullV2 {
		if _, validators, sampleErr := cvAgreementEligibilitySamplesV2Must(s); sampleErr == nil {
			localValidator := false
			for _, validator := range validators {
				if validator == s.cfg.LocalNode {
					localValidator = true
					break
				}
			}
			if !localValidator {
				go s.fetchCandidateWithValidatorFallbackV2(digest, origin, validators)
				return
			}
		}
	}
	request, err := cvEncodeCertifiedCandidateDigestRequestV2(digest)
	if err == nil {
		_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchV2, request, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) fetchCandidateWithValidatorFallbackV2(digest string, origin int, validators []int) {
	request, err := cvEncodeCertifiedCandidateDigestRequestV2(digest)
	if err != nil {
		return
	}
	for _, validator := range validators {
		if validator == s.cfg.LocalNode {
			continue
		}
		if len(s.cachedCertifiedCandidateWireV2(digest)) != 0 {
			return
		}
		_ = s.sendPriorityAsync(validator, cvTagCertifiedCandidateFetchV2, request, nil)
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			timer.Stop()
			return
		}
	}
	if len(s.cachedCertifiedCandidateWireV2(digest)) == 0 && origin != s.cfg.LocalNode {
		_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchV2, request, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) registerCandidateFetchWaiterV2(digest string, requester int) []int {
	if s == nil || len(digest) != 32 || requester < 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	originSet := s.candidateOriginsV2[digest]
	if len(originSet) == 0 {
		return nil
	}
	if s.candidateFetchWaitersV2[digest] == nil {
		if len(s.candidateFetchWaitersV2) >= s.cfg.Params.proposerSampleSize {
			return nil
		}
		s.candidateFetchWaitersV2[digest] = make(map[int]struct{})
	}
	s.candidateFetchWaitersV2[digest][requester] = struct{}{}
	origins := make([]int, 0, len(originSet))
	for origin := range originSet {
		origins = append(origins, origin)
	}
	return origins
}

func cvAgreementEligibilitySamplesV2Must(s *cvAPDBNetworkServiceV2) ([]int, []int, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil candidate service")
	}
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return nil, nil, err
	}
	return append([]int(nil), public.verifiedProposerSample...),
		append([]int(nil), public.verifiedValidatorSample...), nil
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateFetchV2(msg Message) {
	digest, err := cvDecodeCertifiedCandidateDigestRequestV2(msg.Body)
	if err != nil {
		return
	}
	candidate := s.cachedCertifiedCandidateWireV2(digest)
	if len(candidate) == 0 {
		if cvCandidateFanoutModeV2() == cvCandidateFanoutValidatorPullV2 {
			origins := s.registerCandidateFetchWaiterV2(digest, msg.From)
			sort.Ints(origins)
			for _, origin := range origins {
				if origin != msg.From {
					_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchV2, msg.Body, nil)
				}
			}
		}
		return
	}
	response := s.cachedCandidateResponseWireV2(digest, candidate)
	if len(response) != 0 {
		_ = s.sendAsync(msg.From, cvTagCertifiedCandidateResponseV2, response, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateResponseV2(msg Message) {
	digest, candidate, err := cvDecodeCertifiedCandidateResponseV2(msg.Body)
	if err != nil {
		return
	}
	if cvCandidateFanoutModeV2() == cvCandidateFanoutValidatorPullV2 {
		s.mu.Lock()
		waiters := make([]int, 0, len(s.candidateFetchWaitersV2[digest]))
		for peer := range s.candidateFetchWaitersV2[digest] {
			waiters = append(waiters, peer)
		}
		delete(s.candidateFetchWaitersV2, digest)
		s.mu.Unlock()
		// The received response already passed canonical decoding. Reuse its
		// authenticated wire for waiters instead of decoding and re-encoding it.
		response := append([]byte(nil), msg.Body...)
		if len(response) != 0 {
			for _, peer := range waiters {
				_ = s.sendAsync(peer, cvTagCertifiedCandidateResponseV2, response, nil)
			}
		}
	}
	candidateMsg := Message{From: msg.From, To: msg.To, Tag: cvTagCertifiedCandidateV2,
		Body: candidate, WireBytes: msg.WireBytes}
	s.acknowledgeCertifiedCandidateDigestV2(candidateMsg, digest)
	s.enqueueCertifiedCandidateDigestV2(candidateMsg, digest)
}

func (s *cvAPDBNetworkServiceV2) enqueueCertifiedCandidateV2(msg Message) {
	digest := cvCertifiedCandidateDigestV2(msg.Body)
	s.acknowledgeCertifiedCandidateDigestV2(msg, digest)
	s.enqueueCertifiedCandidateDigestV2(msg, digest)
}

func (s *cvAPDBNetworkServiceV2) enqueueCertifiedCandidateDigestV2(msg Message, digest string) {
	s.mu.Lock()
	if cached := s.certifiedCandidatesV2[digest]; len(cached) != 0 && bytes.Equal(cached, msg.Body) {
		s.mu.Unlock()
		return
	}
	if _, inFlight := s.processingCandidatesV2[digest]; inFlight {
		s.mu.Unlock()
		return
	}
	s.processingCandidatesV2[digest] = struct{}{}
	s.mu.Unlock()
	select {
	case s.cryptoQueue <- cvCryptoJobV2{kind: cvCryptoJobCertifiedCandidateV2, msg: msg, digest: digest}:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingCandidatesV2, digest)
		s.mu.Unlock()
	}
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateV2(msg Message) {
	digest := cvCertifiedCandidateDigestV2(msg.Body)
	s.acknowledgeCertifiedCandidateDigestV2(msg, digest)
	s.processCertifiedCandidateDigestV2(msg, digest)
}

func (s *cvAPDBNetworkServiceV2) processCertifiedCandidateV2(msg Message) {
	digest := cvCertifiedCandidateDigestV2(msg.Body)
	s.processCertifiedCandidateDigestV2(msg, digest)
}

func (s *cvAPDBNetworkServiceV2) processCertifiedCandidateDigestV2(msg Message, digest string) {
	if cached := s.cachedCertifiedCandidateWireV2(digest); bytes.Equal(cached, msg.Body) {
		return
	}
	object, accepted, err := s.acceptCertifiedCandidateDigestV2(msg.Body, digest)
	if err != nil {
		return
	}
	if !accepted {
		return
	}
	relayWire := s.cachedCertifiedCandidateWireV2(digest)
	if len(relayWire) == 0 {
		relayWire = append([]byte(nil), msg.Body...)
	}
	mode := cvCandidateFanoutModeV2()
	if mode != cvCandidateFanoutDirectOnlyV2 && mode != cvCandidateFanoutPullV2 && mode != cvCandidateFanoutValidatorPullV2 {
		go func(origin int) {
			_ = s.fanoutCandidateV2(s.ctx, digest, relayWire, msg.From, origin, true)
		}(object.Header.ProposerID)
	}
}
