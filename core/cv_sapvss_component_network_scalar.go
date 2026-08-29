package core

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type cvComponentVerificationResultScalar struct {
	ref          cvComponentRefScalar
	leafDigest   []byte
	payload      []byte
	payloadHints []byte
	leaf         *cvLeafScalar
	recoverErr   error
	verifyErr    error
}

type cvComponentPipelineJobScalar struct {
	index int
	ref   cvComponentRefScalar
}

type cvComponentPipelineResultScalar struct {
	index  int
	result cvComponentVerificationResultScalar
}

func (s *cvAPDBNetworkServiceScalar) PublishComponentScalar(ctx context.Context, leaf *cvLeafScalar) (*cvComponentRefScalar, error) {
	if s == nil || ctx == nil || leaf == nil || s.cfg.LeafContext == nil ||
		!cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) || leaf.DealerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 component publication input")
	}
	payload, err := cvLeafScalarCanonicalBytesAfterValidation(leaf, s.cfg.Receivers, s.cfg.Validators)
	if err != nil {
		return nil, err
	}
	return s.publishComponentPayloadScalar(ctx, payload)
}

func (s *cvAPDBNetworkServiceScalar) PublishBuiltComponentScalar(
	ctx context.Context, material *cvBuiltLeafMaterialScalar,
) (*cvComponentRefScalar, error) {
	if s == nil || ctx == nil || material == nil || material.owner != s || material.leaf == nil ||
		len(material.wire) == 0 || len(material.wire) > s.cfg.MaximumPayload || s.cfg.LeafContext == nil ||
		!cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) || material.leaf.DealerID != s.cfg.LocalNode ||
		!bytes.Equal(material.leaf.Digest, hashBytes([]byte(cvLeafDigestDomainScalar), material.wire)) {
		return nil, fmt.Errorf("invalid built CV V2 component publication input")
	}
	return s.publishComponentPayloadScalar(ctx, material.wire)
}

func (s *cvAPDBNetworkServiceScalar) publishComponentPayloadScalar(
	ctx context.Context, payload []byte,
) (*cvComponentRefScalar, error) {
	instance, err := cvComponentInstanceDigestScalar(s.cfg.ExpectedContext, s.cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	shardBytes := s.cfg.ShardBytes
	s.mu.Unlock()
	encoded, err := cvAPDBEncodeSizedScalar(
		instance, payload, s.cfg.DataShards, s.cfg.TotalShards, shardBytes, s.cfg.MaximumPayload,
	)
	if err != nil {
		return nil, err
	}
	lock, err := s.Lock(ctx, encoded)
	if err != nil {
		return nil, err
	}
	s.cacheDealerPayloadScalar(instance, payload)
	header := cvComponentHeaderScalar{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), DealerID: s.cfg.LocalNode,
		PayloadDigest: cvComponentPayloadDigestScalar(payload), Instance: append([]byte(nil), instance...), Root: append([]byte(nil), lock.Root...),
	}
	ref := &cvComponentRefScalar{Header: header, Lock: *lock}
	if err := cvValidateComponentRefScalar(*ref, s.apdbSigner); err != nil {
		return nil, err
	}
	wire, err := cvComponentRefScalarCanonicalBytes(*ref)
	if err != nil {
		return nil, err
	}
	s.storeComponentRefScalar(*ref)
	s.mu.Lock()
	s.localComponentRefScalar = append([]byte(nil), wire...)
	s.mu.Unlock()
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode {
			_ = s.send(member, cvTagComponentRefScalar, wire)
		}
	}
	return ref, nil
}

// AwaitVerifiedComponentCatalogScalar freezes the first dealer-ordered set of L
// components whose complete APDB payloads pass the unique scalar protocol APVSS verifier.
func (s *cvAPDBNetworkServiceScalar) AwaitVerifiedComponentCatalogScalar(
	ctx context.Context,
) ([]cvComponentRefScalar, error) {
	if s == nil || ctx == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil ||
		!cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 verified component catalog caller")
	}
	s.verifiedCatalogMu.Lock()
	defer s.verifiedCatalogMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.verifiedCatalogScalar) == s.cfg.Params.poolSize {
			catalog := cloneComponentRefsScalar(s.verifiedCatalogScalar)
			s.mu.Unlock()
			return catalog, nil
		}
		verifiedCount := len(s.verifiedComponentsScalar)
		candidates := make([]cvComponentRefScalar, 0, len(s.componentRefsScalar))
		for dealer, ref := range s.componentRefsScalar {
			if _, verified := s.verifiedComponentsScalar[dealer]; verified {
				continue
			}
			if _, rejected := s.rejectedComponentsScalar[dealer]; rejected {
				continue
			}
			candidates = append(candidates, ref)
		}
		updates := s.componentRefUpdatesScalar
		s.mu.Unlock()

		if len(candidates) == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-s.ctx.Done():
				return nil, s.ctx.Err()
			case <-updates:
			}
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].Header.DealerID < candidates[j].Header.DealerID
		})
		needed := s.cfg.Params.poolSize - verifiedCount
		if needed < 1 {
			needed = 1
		}
		if len(candidates) > needed {
			candidates = candidates[:needed]
		}
		s.experimentMu.Lock()
		s.experimentMetrics.proposerCatalogScanCount += len(candidates)
		s.experimentMu.Unlock()
		results := s.recoverAndVerifyComponentPipelineScalar(ctx, candidates)
		var recoveryErr error
		for _, result := range results {
			if result.recoverErr != nil {
				if recoveryErr == nil {
					recoveryErr = result.recoverErr
				}
				continue
			}
			s.mu.Lock()
			dealer := result.ref.Header.DealerID
			if result.verifyErr != nil {
				newRejection := false
				if _, rejected := s.rejectedComponentsScalar[dealer]; !rejected {
					newRejection = true
				}
				s.rejectedComponentsScalar[dealer] = struct{}{}
				if newRejection {
					s.experimentMu.Lock()
					s.experimentMetrics.proposerRejectedCount++
					s.experimentMu.Unlock()
				}
			} else if len(s.verifiedCatalogScalar) == 0 {
				s.storeVerifiedComponentLockedScalar(result.ref, result.leafDigest, result.payload, result.leaf)
			}
			s.mu.Unlock()
		}
		s.mu.Lock()
		if len(s.verifiedCatalogScalar) == 0 && len(s.verifiedComponentsScalar) >= s.cfg.Params.poolSize {
			dealers := make([]int, 0, len(s.verifiedComponentsScalar))
			for dealer := range s.verifiedComponentsScalar {
				dealers = append(dealers, dealer)
			}
			sort.Ints(dealers)
			for _, dealer := range dealers[:s.cfg.Params.poolSize] {
				s.verifiedCatalogScalar = append(s.verifiedCatalogScalar, cloneComponentRefScalar(s.verifiedComponentsScalar[dealer].ref))
			}
		}
		catalogReady := len(s.verifiedCatalogScalar) == s.cfg.Params.poolSize
		catalog := cloneComponentRefsScalar(s.verifiedCatalogScalar)
		s.mu.Unlock()
		if catalogReady {
			return catalog, nil
		}
		if recoveryErr != nil {
			return nil, recoveryErr
		}
	}
}

func (s *cvAPDBNetworkServiceScalar) recoverComponentPayloadScalar(
	ctx context.Context, ref cvComponentRefScalar,
) cvComponentVerificationResultScalar {
	result := cvComponentVerificationResultScalar{ref: cloneComponentRefScalar(ref)}
	payload, hints, err := s.recoveredComponentPayloadScalar(ctx, ref, cvRecoveryProposerCatalogScalar)
	if err != nil {
		result.recoverErr = fmt.Errorf("recover CV V2 component %d: %w", ref.Header.DealerID, err)
		return result
	}
	// recoveredComponentPayloadScalar only returns payloads that are already bound
	// to ref.Header.PayloadDigest. Its cache entries are immutable, and the leaf
	// decoder is read-only; the verified catalog takes its own copy on accept.
	result.payload = payload
	result.payloadHints = hints
	return result
}

func (s *cvAPDBNetworkServiceScalar) verifyRecoveredComponentScalar(
	result cvComponentVerificationResultScalar,
) cvComponentVerificationResultScalar {
	if result.recoverErr != nil || result.verifyErr != nil {
		return result
	}
	ref := result.ref
	payload := result.payload
	leaf, err := cvDecodeLeafScalarWithHints(
		payload, result.payloadHints, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators,
	)
	if err != nil {
		result.verifyErr = fmt.Errorf("invalid CV V2 component %d payload: %w", ref.Header.DealerID, err)
		return result
	}
	if leaf.DealerID != ref.Header.DealerID {
		result.verifyErr = fmt.Errorf("CV V2 component dealer mismatch: leaf=%d ref=%d", leaf.DealerID, ref.Header.DealerID)
		return result
	}
	result.leafDigest = append([]byte(nil), leaf.Digest...)
	result.leaf = leaf
	return result
}

// recoverAndVerifyComponentPipelineScalar keeps network recovery ahead of a fixed
// verifier pool. Each recovered payload flows directly to a verifier instead
// of waiting for a complete verification batch.
func (s *cvAPDBNetworkServiceScalar) recoverAndVerifyComponentPipelineScalar(
	ctx context.Context, refs []cvComponentRefScalar,
) []cvComponentVerificationResultScalar {
	if len(refs) == 0 {
		return nil
	}
	recoveryWorkers := cvComponentRecoveryWorkers(len(refs))
	verificationWorkers := cvLeafVerifyWorkers(len(refs))
	results, verificationLatency := cvRunComponentPipelineScalar(
		refs, recoveryWorkers, verificationWorkers,
		func(ref cvComponentRefScalar) cvComponentVerificationResultScalar {
			return s.recoverComponentPayloadScalar(ctx, ref)
		},
		func(result cvComponentVerificationResultScalar) cvComponentVerificationResultScalar {
			return s.verifyRecoveredComponentScalar(result)
		},
	)
	if verificationLatency > 0 {
		s.experimentMu.Lock()
		s.experimentMetrics.proposerCatalogVerificationLatency += verificationLatency
		s.experimentMu.Unlock()
	}
	return results
}

func cvRunComponentPipelineScalar(
	refs []cvComponentRefScalar, recoveryWorkers, verificationWorkers int,
	recoverComponent func(cvComponentRefScalar) cvComponentVerificationResultScalar,
	verifyComponent func(cvComponentVerificationResultScalar) cvComponentVerificationResultScalar,
) ([]cvComponentVerificationResultScalar, time.Duration) {
	if len(refs) == 0 || recoveryWorkers < 1 || verificationWorkers < 1 ||
		recoverComponent == nil || verifyComponent == nil {
		return nil, 0
	}
	if recoveryWorkers > len(refs) {
		recoveryWorkers = len(refs)
	}
	if verificationWorkers > len(refs) {
		verificationWorkers = len(refs)
	}

	jobs := make(chan cvComponentPipelineJobScalar, recoveryWorkers)
	recovered := make(chan cvComponentPipelineResultScalar, verificationWorkers)
	verified := make(chan cvComponentPipelineResultScalar, verificationWorkers)
	var recoveryWG sync.WaitGroup
	recoveryWG.Add(recoveryWorkers)
	for range recoveryWorkers {
		go func() {
			defer recoveryWG.Done()
			for job := range jobs {
				recovered <- cvComponentPipelineResultScalar{
					index: job.index, result: recoverComponent(job.ref),
				}
			}
		}()
	}
	go func() {
		for index, ref := range refs {
			jobs <- cvComponentPipelineJobScalar{index: index, ref: ref}
		}
		close(jobs)
	}()
	go func() {
		recoveryWG.Wait()
		close(recovered)
	}()

	var verificationWG sync.WaitGroup
	var timingMu sync.Mutex
	var firstStarted, lastFinished time.Time
	verificationWG.Add(verificationWorkers)
	for range verificationWorkers {
		go func() {
			defer verificationWG.Done()
			for item := range recovered {
				started := time.Now()
				result := verifyComponent(item.result)
				finished := time.Now()
				timingMu.Lock()
				if firstStarted.IsZero() || started.Before(firstStarted) {
					firstStarted = started
				}
				if lastFinished.IsZero() || finished.After(lastFinished) {
					lastFinished = finished
				}
				timingMu.Unlock()
				verified <- cvComponentPipelineResultScalar{index: item.index, result: result}
			}
		}()
	}
	go func() {
		verificationWG.Wait()
		close(verified)
	}()

	results := make([]cvComponentVerificationResultScalar, len(refs))
	for item := range verified {
		results[item.index] = item.result
	}
	if firstStarted.IsZero() || lastFinished.Before(firstStarted) {
		return results, 0
	}
	return results, lastFinished.Sub(firstStarted)
}

func (s *cvAPDBNetworkServiceScalar) verifiedComponentLeafScalar(
	ctx context.Context, ref cvComponentRefScalar, purpose cvRecoveryPurposeScalar,
) (*cvLeafScalar, error) {
	dealer := ref.Header.DealerID
	s.mu.Lock()
	if entry, ok := s.verifiedComponentsScalar[dealer]; ok {
		if entry.leaf == nil || !equalComponentRefsScalar(entry.ref, ref) ||
			!bytes.Equal(entry.leaf.Digest, entry.leafDigest) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 verified component cache conflict for dealer %d", dealer)
		}
		leaf := entry.leaf
		s.mu.Unlock()
		return leaf, nil
	}
	if call := s.verifiedComponentCalls[dealer]; call != nil {
		if !equalComponentRefsScalar(call.ref, ref) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 concurrent component conflict for dealer %d", dealer)
		}
		done := call.done
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-done:
			return call.leaf, call.err
		}
	}
	call := &cvVerifiedComponentCallScalar{ref: cloneComponentRefScalar(ref), done: make(chan struct{})}
	s.verifiedComponentCalls[dealer] = call
	s.mu.Unlock()

	payload, hints, err := s.recoveredComponentPayloadScalar(ctx, ref, purpose)
	var leaf *cvLeafScalar
	if err == nil {
		leaf, err = cvDecodeLeafScalarWithHints(
			payload, hints, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators,
		)
		if err == nil && leaf.DealerID != dealer {
			err = fmt.Errorf("CV V2 component dealer mismatch: leaf=%d ref=%d", leaf.DealerID, dealer)
		}
	}

	s.mu.Lock()
	if err == nil {
		s.storeVerifiedComponentLockedScalar(ref, leaf.Digest, payload, leaf)
	}
	call.leaf = leaf
	call.err = err
	delete(s.verifiedComponentCalls, dealer)
	close(call.done)
	s.mu.Unlock()
	return leaf, err
}

// storeVerifiedComponentLockedScalar transfers an authenticated, fully decoded
// payload into the immutable verified cache. The caller must hold s.mu and
// must not mutate payload or leaf after the transfer.
func (s *cvAPDBNetworkServiceScalar) storeVerifiedComponentLockedScalar(
	ref cvComponentRefScalar, leafDigest, payload []byte, leaf *cvLeafScalar,
) {
	if s.verifiedComponentsScalar == nil {
		s.verifiedComponentsScalar = make(map[int]cvVerifiedComponentScalar)
	}
	s.verifiedComponentsScalar[ref.Header.DealerID] = cvVerifiedComponentScalar{
		ref: cloneComponentRefScalar(ref), leafDigest: append([]byte(nil), leafDigest...),
		payload: payload, leaf: leaf,
	}
	// The verified entry is checked first by recoveredComponentPayloadScalar, so
	// its earlier recovery payload and decode hints are now redundant.
	delete(s.recoveredPayloadsScalar, cvRecoveredComponentPayloadKeyScalar(ref))
}

func (s *cvAPDBNetworkServiceScalar) VerifiedComponentLeavesScalar(
	pool *cvPoolScalar, selected []int,
) ([]*cvLeafScalar, error) {
	if s == nil || pool == nil || len(selected) != s.cfg.Params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 verified component selection")
	}
	leaves := make([]*cvLeafScalar, len(selected))
	seen := make(map[int]struct{}, len(selected))
	if _, err := cvPoolScalarCanonicalBytes(pool, s.cfg.Params); err != nil {
		return nil, fmt.Errorf("invalid CV V2 verified component Pool: %w", err)
	}
	s.mu.Lock()
	if len(s.verifiedCatalogScalar) != s.cfg.Params.poolSize || len(pool.Components) != len(s.verifiedCatalogScalar) {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 Pool does not match frozen verified catalog")
	}
	for i := range s.verifiedCatalogScalar {
		if !equalComponentRefsScalar(s.verifiedCatalogScalar[i], pool.Components[i]) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 Pool does not match frozen verified catalog")
		}
	}
	for i, poolIndex := range selected {
		if poolIndex < 0 || poolIndex >= len(pool.Components) {
			s.mu.Unlock()
			return nil, fmt.Errorf("invalid CV V2 verified component pool index")
		}
		if _, duplicate := seen[poolIndex]; duplicate {
			s.mu.Unlock()
			return nil, fmt.Errorf("duplicate CV V2 verified component pool index")
		}
		seen[poolIndex] = struct{}{}
		ref := pool.Components[poolIndex]
		entry, ok := s.verifiedComponentsScalar[ref.Header.DealerID]
		if !ok || !equalComponentRefsScalar(entry.ref, ref) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 pool component is outside verified catalog")
		}
		if entry.leaf == nil || !bytes.Equal(entry.leaf.Digest, entry.leafDigest) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 verified component leaf cache mismatch")
		}
		leaves[i] = entry.leaf
	}
	s.mu.Unlock()
	return leaves, nil
}

func (s *cvAPDBNetworkServiceScalar) storeComponentRefScalar(ref cvComponentRefScalar) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.componentRefsScalar[ref.Header.DealerID]; exists {
		return false
	}
	s.componentRefsScalar[ref.Header.DealerID] = ref
	cvNotifyAPDBScalar(s.componentRefUpdatesScalar)
	return true
}

func cloneComponentRefScalar(ref cvComponentRefScalar) cvComponentRefScalar {
	return cvComponentRefScalar{
		Header: cvComponentHeaderScalar{
			ContextDigest: append([]byte(nil), ref.Header.ContextDigest...), DealerID: ref.Header.DealerID,
			PayloadDigest: append([]byte(nil), ref.Header.PayloadDigest...),
			Instance:      append([]byte(nil), ref.Header.Instance...), Root: append([]byte(nil), ref.Header.Root...),
		},
		Lock: cvAPDBLockScalar{
			InstanceDigest: append([]byte(nil), ref.Lock.InstanceDigest...), Root: append([]byte(nil), ref.Lock.Root...),
			Certificate: append([]byte(nil), ref.Lock.Certificate...),
		},
	}
}

func cloneComponentRefsScalar(refs []cvComponentRefScalar) []cvComponentRefScalar {
	cloned := make([]cvComponentRefScalar, len(refs))
	for i := range refs {
		cloned[i] = cloneComponentRefScalar(refs[i])
	}
	return cloned
}

func equalComponentRefsScalar(left, right cvComponentRefScalar) bool {
	leftWire, leftErr := cvComponentRefScalarCanonicalBytes(left)
	rightWire, rightErr := cvComponentRefScalarCanonicalBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func (s *cvAPDBNetworkServiceScalar) handleComponentRefScalar(msg Message) {
	// The authenticated transport already binds msg.From to the dealer. Once
	// that dealer's reference is known, duplicate announcements need no decode;
	// the existing path also ignored replacement wires for known dealers.
	s.mu.Lock()
	knownDealer := false
	if _, ok := s.componentRefsScalar[msg.From]; ok {
		knownDealer = true
	}
	s.mu.Unlock()
	if knownDealer {
		return
	}
	ref, err := cvDecodeComponentRefScalar(msg.Body)
	if err != nil || ref.Header.DealerID != msg.From || !bytes.Equal(ref.Header.ContextDigest, s.cfg.ExpectedContext) {
		return
	}
	if err := cvValidateComponentRefScalar(ref, s.apdbSigner); err != nil {
		return
	}
	if !s.storeComponentRefScalar(ref) {
		return
	}
	s.mu.Lock()
	localWire := append([]byte(nil), s.localComponentRefScalar...)
	s.mu.Unlock()
	if len(localWire) != 0 && msg.From != s.cfg.LocalNode {
		_ = s.send(msg.From, cvTagComponentRefScalar, localWire)
	}
}
