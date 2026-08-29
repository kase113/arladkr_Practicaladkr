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

const cvCertifiedCandidateDigestScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/certified-candidate-digest"

const (
	cvCertifiedCandidateACKScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/certified-candidate-ack"
	cvCandidateFanoutMaxAttemptsScalar  = 4
	cvCandidateFanoutRetryBaseScalar    = 250 * time.Millisecond
)

const (
	cvCandidateFanoutFloodScalar         = "flood"
	cvCandidateFanoutDirectOnlyScalar    = "direct-only"
	cvCandidateFanoutTreeScalar          = "tree"
	cvCandidateFanoutPullScalar          = "pull"
	cvCandidateFanoutValidatorPullScalar = "validator-pull"
)

func cvCandidateFanoutModeScalar() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_CANDIDATE_FANOUT_MODE")))
	if mode == cvCandidateFanoutDirectOnlyScalar || mode == cvCandidateFanoutTreeScalar || mode == cvCandidateFanoutPullScalar || mode == cvCandidateFanoutValidatorPullScalar {
		return mode
	}
	return cvCandidateFanoutFloodScalar
}

const (
	cvCertifiedCandidateAnnounceDomainScalar = "ARL-CV-sAPVSS/v2/candidate-announce"
	cvCertifiedCandidateFetchDomainScalar    = "ARL-CV-sAPVSS/v2/candidate-fetch"
	cvCertifiedCandidateResponseDomainScalar = "ARL-CV-sAPVSS/v2/candidate-response"
)

func cvEncodeCertifiedCandidateAnnounceScalar(origin int, digest string) ([]byte, error) {
	if origin < 0 || len(digest) != 32 {
		return nil, fmt.Errorf("invalid candidate announce")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateAnnounceDomainScalar))
	cvWriteUint64(&wire, uint64(origin))
	_ = cvWriteBytes(&wire, []byte(digest))
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateAnnounceScalar(wire []byte) (int, string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateAnnounceDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateAnnounceDomainScalar)) {
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

func cvEncodeCertifiedCandidateDigestRequestScalar(digest string) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid candidate fetch digest")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateFetchDomainScalar))
	_ = cvWriteBytes(&wire, []byte(digest))
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateDigestRequestScalar(wire []byte) (string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateFetchDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateFetchDomainScalar)) {
		return "", fmt.Errorf("invalid candidate fetch domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return "", fmt.Errorf("invalid candidate fetch digest")
	}
	return string(digest), nil
}

func cvEncodeCertifiedCandidateResponseScalar(digest string, candidate []byte) ([]byte, error) {
	if len(digest) != 32 || len(candidate) == 0 {
		return nil, fmt.Errorf("invalid candidate response")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedCandidateResponseDomainScalar))
	_ = cvWriteBytes(&wire, []byte(digest))
	_ = cvWriteBytes(&wire, candidate)
	return wire.Bytes(), nil
}

func cvDecodeCertifiedCandidateResponseScalar(wire []byte) (string, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedCandidateResponseDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedCandidateResponseDomainScalar)) {
		return "", nil, fmt.Errorf("invalid candidate response domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return "", nil, fmt.Errorf("invalid candidate response digest")
	}
	candidate, err := r.bytes(cvMaxAgreementObjectScalarBytes)
	if err != nil || len(candidate) == 0 || r.reader.Len() != 0 {
		return "", nil, fmt.Errorf("invalid candidate response payload")
	}
	if cvCertifiedCandidateDigestScalar(candidate) != string(digest) {
		return "", nil, fmt.Errorf("candidate response digest mismatch")
	}
	return string(digest), candidate, nil
}

func cvCandidateFanoutParallelScalar(peers int) int {
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

type cvCandidateResponseCallScalar struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvCandidateFanoutStateScalar struct {
	mu       sync.Mutex
	acked    map[int]struct{}
	waiters  map[int]chan struct{}
	ackProbe []byte
	refs     int
}

func (s *cvCandidateFanoutStateScalar) markACK(peer int) {
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

func (s *cvCandidateFanoutStateScalar) isACKed(peer int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	_, ok := s.acked[peer]
	s.mu.Unlock()
	return ok
}

func (s *cvCandidateFanoutStateScalar) ackedSignal(peer int) <-chan struct{} {
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

func cvCertifiedCandidateDigestScalar(wire []byte) string {
	return string(hashBytes([]byte(cvCertifiedCandidateDigestScalarDomain), wire))
}

func cvEncodeCertifiedCandidateACKScalar(digest string) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 certified candidate ACK digest")
	}
	wire := make([]byte, len(cvCertifiedCandidateACKScalarDomain)+len(digest))
	copy(wire, []byte(cvCertifiedCandidateACKScalarDomain))
	copy(wire[len(cvCertifiedCandidateACKScalarDomain):], []byte(digest))
	return wire, nil
}

func cvDecodeCertifiedCandidateACKScalar(wire []byte) (string, error) {
	domain := []byte(cvCertifiedCandidateACKScalarDomain)
	if len(wire) != len(domain)+32 || !bytes.Equal(wire[:len(domain)], domain) {
		return "", fmt.Errorf("invalid CV V2 certified candidate ACK")
	}
	return string(wire[len(domain):]), nil
}

func (s *cvAPDBNetworkServiceScalar) candidateFanoutStateScalar(digest string) *cvCandidateFanoutStateScalar {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidateFanoutScalar == nil {
		s.candidateFanoutScalar = make(map[string]*cvCandidateFanoutStateScalar)
	}
	state := s.candidateFanoutScalar[digest]
	if state == nil {
		probe, _ := cvEncodeCertifiedCandidateACKScalar(digest)
		state = &cvCandidateFanoutStateScalar{
			acked: make(map[int]struct{}), waiters: make(map[int]chan struct{}), ackProbe: probe,
		}
		s.candidateFanoutScalar[digest] = state
	}
	state.refs++
	return state
}

func (s *cvAPDBNetworkServiceScalar) releaseCandidateFanoutStateScalar(digest string, state *cvCandidateFanoutStateScalar) {
	if s == nil || state == nil {
		return
	}
	s.mu.Lock()
	if current := s.candidateFanoutScalar[digest]; current == state {
		state.refs--
		if state.refs <= 0 {
			delete(s.candidateFanoutScalar, digest)
		}
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) markCertifiedCandidateACKScalar(digest string, peer int) {
	if s == nil || len(digest) != 32 {
		return
	}
	s.mu.Lock()
	state := s.candidateFanoutScalar[digest]
	s.mu.Unlock()
	if state != nil {
		state.markACK(peer)
	}
}

func (s *cvAPDBNetworkServiceScalar) cachedCertifiedCandidateWireScalar(digest string) []byte {
	if s == nil || digest == "" {
		return nil
	}
	s.mu.Lock()
	wire := append([]byte(nil), s.certifiedCandidatesScalar[digest]...)
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceScalar) waitCertifiedCandidateACKScalar(
	ctx context.Context, state *cvCandidateFanoutStateScalar, peer int, delay time.Duration,
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

func (s *cvAPDBNetworkServiceScalar) sendCertifiedCandidatePeerScalar(
	ctx context.Context, state *cvCandidateFanoutStateScalar, peer int, digest string, wire []byte, probeFirst bool,
) error {
	started := time.Now()
	defer func() { s.recordCandidateFanoutPeerLatencyScalar(time.Since(started)) }()
	// ackProbe is immutable for this digest and safe for concurrent readers.
	probe := state.ackProbe
	if len(probe) == 0 {
		var err error
		probe, err = cvEncodeCertifiedCandidateACKScalar(digest)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < cvCandidateFanoutMaxAttemptsScalar; attempt++ {
		if state.isACKed(peer) {
			return nil
		}
		delay := cvCandidateFanoutRetryBaseScalar << attempt
		tag, payload := cvCandidateFanoutAttemptScalar(attempt, probeFirst, probe, wire)
		if err := s.send(peer, tag, payload); err == nil {
			waitStarted := time.Now()
			acknowledged := s.waitCertifiedCandidateACKScalar(ctx, state, peer, delay)
			canceled := ctx.Err() != nil || s.ctx.Err() != nil
			s.recordCandidateFanoutAttemptScalar(time.Since(waitStarted), !acknowledged && !canceled)
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
			s.recordCandidateFanoutAttemptScalar(time.Since(waitStarted), true)
		}
	}
	if state.isACKed(peer) {
		return nil
	}
	return fmt.Errorf("CV V2 candidate ACK timeout from peer %d for %x", peer, []byte(digest))
}

func cvCandidateFanoutAttemptScalar(attempt int, probeFirst bool, probe, wire []byte) (string, []byte) {
	probeAttempt := attempt%2 == 1
	if probeFirst {
		probeAttempt = attempt%2 == 0
	}
	if probeAttempt {
		return cvTagCertifiedCandidateACKProbeScalar, probe
	}
	return cvTagCertifiedCandidateScalar, wire
}

// fanoutCandidateScalar sends one canonical candidate to each peer with bounded
// parallelism. A peer is retried only until it ACKs or the bounded attempt
// budget is exhausted; successful peers are never included in later retries.
func (s *cvAPDBNetworkServiceScalar) fanoutCandidateScalar(
	ctx context.Context, digest string, wire []byte, excluded, origin int, probeFirst bool,
) error {
	if s == nil || ctx == nil || len(digest) != 32 || len(wire) == 0 {
		return fmt.Errorf("invalid CV V2 candidate fanout")
	}
	mode := cvCandidateFanoutModeScalar()
	if mode == cvCandidateFanoutPullScalar || mode == cvCandidateFanoutValidatorPullScalar {
		if mode == cvCandidateFanoutValidatorPullScalar {
			if _, validators, sampleErr := cvAgreementEligibilitySamplesScalarMust(s); sampleErr == nil {
				// Prefetch the complete authenticated candidate into every validator
				// before announcing the digest. Validators then form a recovery set
				// if the proposer disappears after publication.
				for _, validator := range validators {
					if validator != s.cfg.LocalNode {
						if err := s.send(validator, cvTagCertifiedCandidateScalar, wire); err != nil {
							return err
						}
					}
				}
			}
		}
		announce, err := cvEncodeCertifiedCandidateAnnounceScalar(origin, digest)
		if err != nil {
			return err
		}
		for _, peer := range cvCandidateFanoutPeersScalar(s.cfg.OldRoster, s.cfg.LocalNode, excluded, origin, cvCandidateFanoutDirectOnlyScalar) {
			if err := s.send(peer, cvTagCertifiedCandidateAnnounceScalar, announce); err != nil {
				return err
			}
		}
		return nil
	}
	peers := cvCandidateFanoutPeersScalar(s.cfg.OldRoster, s.cfg.LocalNode, excluded, origin, mode)
	if len(peers) == 0 {
		return nil
	}
	state := s.candidateFanoutStateScalar(digest)
	defer s.releaseCandidateFanoutStateScalar(digest, state)
	parallel := cvCandidateFanoutParallelScalar(len(peers))
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
			errs <- s.sendCertifiedCandidatePeerScalar(ctx, state, peer, digest, wire, probeFirst)
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

func cvCandidateFanoutPeersScalar(roster []int, local, excluded, origin int, mode string) []int {
	ordered := append([]int(nil), roster...)
	sort.Ints(ordered)
	if mode != cvCandidateFanoutTreeScalar {
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

func (s *cvAPDBNetworkServiceScalar) agreementPublicContextScalar() (cvAgreementPublicContextScalar, error) {
	if s == nil {
		return cvAgreementPublicContextScalar{}, fmt.Errorf("nil CV V2 candidate service")
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
		return cvAgreementPublicContextScalar{}, fmt.Errorf("CV V2 eligibility coin is not available")
	}
	public := cvAgreementPublicContextScalar{
		SID: s.cfg.SID, Epoch: s.cfg.Epoch, ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...),
		OldCommittee: append([]int(nil), s.cfg.OldRoster...), EligibilityCoin: coin, Params: s.cfg.Params,
		APDBSigner: s.apdbSigner, ControlSigner: s.controlSigner, CoinSigner: s.coinSigner,
		ValidatorKeys: s.cfg.Validators, verifiedProposerSample: proposers,
		verifiedValidatorSample: validators, eligibilityVerified: true,
		verifiedCandidate: s.isVerifiedCertifiedCandidateScalar,
	}
	if _, _, err := cvAgreementEligibilitySamplesScalar(public); err != nil {
		return cvAgreementPublicContextScalar{}, err
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

func (s *cvAPDBNetworkServiceScalar) isVerifiedCertifiedCandidateScalar(wire []byte) bool {
	if s == nil || len(wire) == 0 {
		return false
	}
	digest := cvCertifiedCandidateDigestScalar(wire)
	s.mu.Lock()
	cached := s.certifiedCandidatesScalar[digest]
	s.mu.Unlock()
	return bytes.Equal(cached, wire)
}

func (s *cvAPDBNetworkServiceScalar) acceptCertifiedCandidateScalar(wire []byte) (*cvAgreementObjectScalar, bool, error) {
	digest := cvCertifiedCandidateDigestScalar(wire)
	return s.acceptCertifiedCandidateDigestScalar(wire, digest)
}

func (s *cvAPDBNetworkServiceScalar) acceptCertifiedCandidateDigestScalar(
	wire []byte, digest string,
) (*cvAgreementObjectScalar, bool, error) {
	if digest == "" {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate digest")
	}
	s.mu.Lock()
	cached := s.certifiedCandidatesScalar[digest]
	s.mu.Unlock()
	if len(cached) != 0 {
		if bytes.Equal(cached, wire) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("conflicting CV V2 certified candidate digest")
	}
	public, err := s.agreementPublicContextScalar()
	if err != nil {
		return nil, false, err
	}
	// agreementPublicContextScalar validates and snapshots the eligibility samples;
	// reuse that immutable snapshot instead of repeating the same checks.
	validators := append([]int(nil), public.verifiedValidatorSample...)
	object, err := cvDecodeAgreementObjectScalar(wire, s.cfg.Params, validators)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate")
	}
	canonical, err := cvValidateAgreementObjectScalar(object, public)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate")
	}
	// Normalize the cached representation to the locally selected wire mode.
	// The transport digest remains tied to the actual wire bytes, preserving
	// authenticated fetch semantics during a rolling deployment.
	if !bytes.Equal(canonical, wire) {
		digest = cvCertifiedCandidateDigestScalar(canonical)
	}
	return s.rememberVerifiedCertifiedCandidateScalar(object, digest, canonical)
}

// rememberVerifiedCertifiedCandidateScalar is only for an object that was
// canonicalized and fully verified immediately before this call. Network
// input must use acceptCertifiedCandidateScalar so the provenance cannot be
// forged by an untrusted wire payload.
func (s *cvAPDBNetworkServiceScalar) rememberVerifiedCertifiedCandidateScalar(
	object *cvAgreementObjectScalar, digest string, canonical []byte,
) (*cvAgreementObjectScalar, bool, error) {
	if object == nil || digest == "" || len(canonical) == 0 {
		return nil, false, fmt.Errorf("invalid verified CV V2 certified candidate")
	}
	s.mu.Lock()
	if existingDigest := s.candidateDigestByProposerScalar[object.Header.ProposerID]; existingDigest != "" && existingDigest != digest {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("conflicting CV V2 candidate for proposer")
	}
	if existing := s.certifiedCandidatesScalar[digest]; len(existing) != 0 {
		s.mu.Unlock()
		if bytes.Equal(existing, canonical) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("conflicting CV V2 certified candidate digest")
	}
	s.candidateDigestByProposerScalar[object.Header.ProposerID] = digest
	s.certifiedCandidatesScalar[digest] = append([]byte(nil), canonical...)
	s.mu.Unlock()
	select {
	case s.certifiedCandidateChScalar <- object:
	case <-s.ctx.Done():
		return nil, false, s.ctx.Err()
	}
	return object, true, nil
}

func (s *cvAPDBNetworkServiceScalar) registerCandidateOriginScalar(origin int, digest string) bool {
	if s == nil || origin < 0 || len(digest) != 32 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, eligible := s.eligibleProposers[origin]; !eligible {
		return false
	}
	if _, exists := s.candidateDigestByProposerScalar[origin]; exists {
		return false
	}
	if len(s.candidateDigestByProposerScalar) >= s.cfg.Params.proposerSampleSize {
		return false
	}
	s.candidateDigestByProposerScalar[origin] = digest
	if s.candidateOriginsScalar[digest] == nil {
		s.candidateOriginsScalar[digest] = make(map[int]struct{}, 1)
	}
	s.candidateOriginsScalar[digest][origin] = struct{}{}
	return true
}

func (s *cvAPDBNetworkServiceScalar) acceptVerifiedCertifiedCandidateScalar(
	object *cvAgreementObjectScalar, canonical []byte,
) (*cvAgreementObjectScalar, bool, error) {
	if object == nil || len(canonical) == 0 {
		return nil, false, fmt.Errorf("invalid verified CV V2 certified candidate")
	}
	digest := cvCertifiedCandidateDigestScalar(canonical)
	return s.rememberVerifiedCertifiedCandidateScalar(object, digest, canonical)
}

func (s *cvAPDBNetworkServiceScalar) PublishCertifiedCandidateScalar(
	ctx context.Context, candidate *cvAgreementObjectScalar,
) error {
	if s == nil || ctx == nil || candidate == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) {
		return fmt.Errorf("invalid CV V2 certified candidate publisher")
	}
	public, err := s.agreementPublicContextScalar()
	if err != nil {
		return err
	}
	wire, err := cvValidateAgreementObjectScalar(candidate, public)
	if err != nil {
		return fmt.Errorf("invalid local CV V2 certified candidate")
	}
	if _, _, err := s.acceptVerifiedCertifiedCandidateScalar(candidate, wire); err != nil {
		return err
	}
	digest := cvCertifiedCandidateDigestScalar(wire)
	if cached := s.cachedCertifiedCandidateWireScalar(digest); len(cached) != 0 {
		wire = cached
	}
	if err := s.fanoutCandidateScalar(ctx, digest, wire, -1, candidate.Header.ProposerID, false); err != nil {
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

// publishLocallyCertifiedCandidateScalar is restricted to the proposer pipeline,
// after CertifyAggregate has validated the Pool, contributor coin, ARC and
// recovered VCert. Network-originated candidates must use the full verifier.
func (s *cvAPDBNetworkServiceScalar) publishLocallyCertifiedCandidateScalar(
	ctx context.Context, candidate *cvAgreementObjectScalar,
) error {
	if s == nil || ctx == nil || candidate == nil || candidate.Header.ProposerID != s.cfg.LocalNode {
		return fmt.Errorf("invalid locally certified CV V2 candidate")
	}
	public, err := s.agreementPublicContextScalar()
	if err != nil {
		return err
	}
	// The context constructor already validated the cached sample.
	validators := append([]int(nil), public.verifiedValidatorSample...)
	wire, err := cvAgreementObjectScalarWireBytes(candidate, s.cfg.Params, validators)
	if err != nil {
		return err
	}
	if _, _, err := s.acceptVerifiedCertifiedCandidateScalar(candidate, wire); err != nil {
		return err
	}
	digest := cvCertifiedCandidateDigestScalar(wire)
	if err := s.fanoutCandidateScalar(ctx, digest, wire, -1, candidate.Header.ProposerID, false); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *cvAPDBNetworkServiceScalar) AwaitFirstCertifiedCandidateScalar(
	ctx context.Context,
) (*cvAgreementObjectScalar, error) {
	if s == nil || ctx == nil {
		return nil, fmt.Errorf("invalid CV V2 certified candidate wait")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case candidate := <-s.certifiedCandidateChScalar:
		return candidate, nil
	}
}

func (s *cvAPDBNetworkServiceScalar) CertifiedCandidateCountScalar() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certifiedCandidatesScalar)
}

func (s *cvAPDBNetworkServiceScalar) acknowledgeCertifiedCandidateDigestScalar(msg Message, digest string) {
	// This ACK confirms delivery of an authenticated envelope, not candidate
	// validity. Sending it before expensive verification avoids WAN retries
	// while preserving the verification gate below.
	if ack := s.cachedCandidateACKWireScalar(digest); len(ack) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagCertifiedCandidateACKScalar, ack, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) cachedCandidateACKWireScalar(digest string) []byte {
	if s == nil || len(digest) != 32 {
		return nil
	}
	s.mu.Lock()
	if wire := s.candidateACKWiresScalar[digest]; len(wire) != 0 {
		s.mu.Unlock()
		return wire
	}
	wire, err := cvEncodeCertifiedCandidateACKScalar(digest)
	if err == nil {
		if s.candidateACKWiresScalar == nil {
			s.candidateACKWiresScalar = make(map[string][]byte)
		}
		s.candidateACKWiresScalar[digest] = wire
	}
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceScalar) cachedCandidateResponseWireScalar(digest string, candidate []byte) []byte {
	if s == nil || len(digest) != 32 || len(candidate) == 0 {
		return nil
	}
	s.mu.Lock()
	if wire := s.candidateResponseWiresScalar[digest]; len(wire) != 0 {
		s.mu.Unlock()
		return wire
	}
	if call := s.candidateResponseCallsScalar[digest]; call != nil {
		s.mu.Unlock()
		select {
		case <-s.ctx.Done():
			return nil
		case <-call.ready:
			return call.response
		}
	}
	call := &cvCandidateResponseCallScalar{ready: make(chan struct{})}
	if s.candidateResponseCallsScalar == nil {
		s.candidateResponseCallsScalar = make(map[string]*cvCandidateResponseCallScalar)
	}
	s.candidateResponseCallsScalar[digest] = call
	s.mu.Unlock()
	wire, err := cvEncodeCertifiedCandidateResponseScalar(digest, candidate)
	s.mu.Lock()
	if err == nil {
		if s.candidateResponseWiresScalar == nil {
			s.candidateResponseWiresScalar = make(map[string][]byte)
		}
		s.candidateResponseWiresScalar[digest] = wire
	}
	call.response = wire
	call.err = err
	delete(s.candidateResponseCallsScalar, digest)
	close(call.ready)
	s.mu.Unlock()
	return wire
}

func (s *cvAPDBNetworkServiceScalar) handleCertifiedCandidateACKProbeScalar(msg Message) {
	digest, err := cvDecodeCertifiedCandidateACKScalar(msg.Body)
	if err != nil || !s.hasDeliveredCertifiedCandidateScalar(digest) {
		return
	}
	if ack := s.cachedCandidateACKWireScalar(digest); len(ack) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagCertifiedCandidateACKScalar, ack, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) hasDeliveredCertifiedCandidateScalar(digest string) bool {
	if s == nil || len(digest) != 32 {
		return false
	}
	s.mu.Lock()
	_, processing := s.processingCandidatesScalar[digest]
	delivered := processing || len(s.certifiedCandidatesScalar[digest]) != 0
	s.mu.Unlock()
	return delivered
}

func (s *cvAPDBNetworkServiceScalar) handleCertifiedCandidateAnnounceScalar(msg Message) {
	origin, digest, err := cvDecodeCertifiedCandidateAnnounceScalar(msg.Body)
	if err != nil || origin != msg.From || len(s.cachedCertifiedCandidateWireScalar(digest)) != 0 {
		return
	}
	if !s.registerCandidateOriginScalar(origin, digest) {
		return
	}
	if cvCandidateFanoutModeScalar() == cvCandidateFanoutValidatorPullScalar {
		if _, validators, sampleErr := cvAgreementEligibilitySamplesScalarMust(s); sampleErr == nil {
			localValidator := false
			for _, validator := range validators {
				if validator == s.cfg.LocalNode {
					localValidator = true
					break
				}
			}
			if !localValidator {
				go s.fetchCandidateWithValidatorFallbackScalar(digest, origin, validators)
				return
			}
		}
	}
	request, err := cvEncodeCertifiedCandidateDigestRequestScalar(digest)
	if err == nil {
		_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchScalar, request, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) fetchCandidateWithValidatorFallbackScalar(digest string, origin int, validators []int) {
	request, err := cvEncodeCertifiedCandidateDigestRequestScalar(digest)
	if err != nil {
		return
	}
	for _, validator := range validators {
		if validator == s.cfg.LocalNode {
			continue
		}
		if len(s.cachedCertifiedCandidateWireScalar(digest)) != 0 {
			return
		}
		_ = s.sendPriorityAsync(validator, cvTagCertifiedCandidateFetchScalar, request, nil)
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			timer.Stop()
			return
		}
	}
	if len(s.cachedCertifiedCandidateWireScalar(digest)) == 0 && origin != s.cfg.LocalNode {
		_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchScalar, request, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) registerCandidateFetchWaiterScalar(digest string, requester int) []int {
	if s == nil || len(digest) != 32 || requester < 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	originSet := s.candidateOriginsScalar[digest]
	if len(originSet) == 0 {
		return nil
	}
	if s.candidateFetchWaitersScalar[digest] == nil {
		if len(s.candidateFetchWaitersScalar) >= s.cfg.Params.proposerSampleSize {
			return nil
		}
		s.candidateFetchWaitersScalar[digest] = make(map[int]struct{})
	}
	s.candidateFetchWaitersScalar[digest][requester] = struct{}{}
	origins := make([]int, 0, len(originSet))
	for origin := range originSet {
		origins = append(origins, origin)
	}
	return origins
}

func cvAgreementEligibilitySamplesScalarMust(s *cvAPDBNetworkServiceScalar) ([]int, []int, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil candidate service")
	}
	public, err := s.agreementPublicContextScalar()
	if err != nil {
		return nil, nil, err
	}
	return append([]int(nil), public.verifiedProposerSample...),
		append([]int(nil), public.verifiedValidatorSample...), nil
}

func (s *cvAPDBNetworkServiceScalar) handleCertifiedCandidateFetchScalar(msg Message) {
	digest, err := cvDecodeCertifiedCandidateDigestRequestScalar(msg.Body)
	if err != nil {
		return
	}
	candidate := s.cachedCertifiedCandidateWireScalar(digest)
	if len(candidate) == 0 {
		if cvCandidateFanoutModeScalar() == cvCandidateFanoutValidatorPullScalar {
			origins := s.registerCandidateFetchWaiterScalar(digest, msg.From)
			sort.Ints(origins)
			for _, origin := range origins {
				if origin != msg.From {
					_ = s.sendPriorityAsync(origin, cvTagCertifiedCandidateFetchScalar, msg.Body, nil)
				}
			}
		}
		return
	}
	response := s.cachedCandidateResponseWireScalar(digest, candidate)
	if len(response) != 0 {
		_ = s.sendAsync(msg.From, cvTagCertifiedCandidateResponseScalar, response, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) handleCertifiedCandidateResponseScalar(msg Message) {
	digest, candidate, err := cvDecodeCertifiedCandidateResponseScalar(msg.Body)
	if err != nil {
		return
	}
	if cvCandidateFanoutModeScalar() == cvCandidateFanoutValidatorPullScalar {
		s.mu.Lock()
		waiters := make([]int, 0, len(s.candidateFetchWaitersScalar[digest]))
		for peer := range s.candidateFetchWaitersScalar[digest] {
			waiters = append(waiters, peer)
		}
		delete(s.candidateFetchWaitersScalar, digest)
		s.mu.Unlock()
		// The received response already passed canonical decoding. Reuse its
		// authenticated wire for waiters instead of decoding and re-encoding it.
		response := append([]byte(nil), msg.Body...)
		if len(response) != 0 {
			for _, peer := range waiters {
				_ = s.sendAsync(peer, cvTagCertifiedCandidateResponseScalar, response, nil)
			}
		}
	}
	candidateMsg := Message{From: msg.From, To: msg.To, Tag: cvTagCertifiedCandidateScalar,
		Body: candidate, WireBytes: msg.WireBytes}
	s.acknowledgeCertifiedCandidateDigestScalar(candidateMsg, digest)
	s.enqueueCertifiedCandidateDigestScalar(candidateMsg, digest)
}

func (s *cvAPDBNetworkServiceScalar) enqueueCertifiedCandidateScalar(msg Message) {
	digest := cvCertifiedCandidateDigestScalar(msg.Body)
	s.acknowledgeCertifiedCandidateDigestScalar(msg, digest)
	s.enqueueCertifiedCandidateDigestScalar(msg, digest)
}

func (s *cvAPDBNetworkServiceScalar) enqueueCertifiedCandidateDigestScalar(msg Message, digest string) {
	s.mu.Lock()
	if cached := s.certifiedCandidatesScalar[digest]; len(cached) != 0 && bytes.Equal(cached, msg.Body) {
		s.mu.Unlock()
		return
	}
	if _, inFlight := s.processingCandidatesScalar[digest]; inFlight {
		s.mu.Unlock()
		return
	}
	s.processingCandidatesScalar[digest] = struct{}{}
	s.mu.Unlock()
	select {
	case s.cryptoQueue <- cvCryptoJobScalar{kind: cvCryptoJobCertifiedCandidateScalar, msg: msg, digest: digest}:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingCandidatesScalar, digest)
		s.mu.Unlock()
	}
}

func (s *cvAPDBNetworkServiceScalar) handleCertifiedCandidateScalar(msg Message) {
	digest := cvCertifiedCandidateDigestScalar(msg.Body)
	s.acknowledgeCertifiedCandidateDigestScalar(msg, digest)
	s.processCertifiedCandidateDigestScalar(msg, digest)
}

func (s *cvAPDBNetworkServiceScalar) processCertifiedCandidateDigestScalar(msg Message, digest string) {
	if cached := s.cachedCertifiedCandidateWireScalar(digest); bytes.Equal(cached, msg.Body) {
		return
	}
	object, accepted, err := s.acceptCertifiedCandidateDigestScalar(msg.Body, digest)
	if err != nil {
		return
	}
	if !accepted {
		return
	}
	relayWire := s.cachedCertifiedCandidateWireScalar(digest)
	if len(relayWire) == 0 {
		relayWire = append([]byte(nil), msg.Body...)
	}
	mode := cvCandidateFanoutModeScalar()
	if mode != cvCandidateFanoutDirectOnlyScalar && mode != cvCandidateFanoutPullScalar && mode != cvCandidateFanoutValidatorPullScalar {
		go func(origin int) {
			_ = s.fanoutCandidateScalar(s.ctx, digest, relayWire, msg.From, origin, true)
		}(object.Header.ProposerID)
	}
}
