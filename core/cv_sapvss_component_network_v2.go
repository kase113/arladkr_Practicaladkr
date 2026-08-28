package core

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type cvComponentVerificationResultV2 struct {
	ref          cvComponentRefV2
	leafDigest   []byte
	payload      []byte
	payloadHints []byte
	leaf         *cvLeafV2
	recoverErr   error
	verifyErr    error
}

type cvComponentPipelineJobV2 struct {
	index int
	ref   cvComponentRefV2
}

type cvComponentPipelineResultV2 struct {
	index  int
	result cvComponentVerificationResultV2
}

func (s *cvAPDBNetworkServiceV2) PublishComponentV2(ctx context.Context, leaf *cvLeafV2) (*cvComponentRefV2, error) {
	if s == nil || ctx == nil || leaf == nil || s.cfg.LeafContext == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) || leaf.DealerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 component publication input")
	}
	payload, err := cvLeafV2CanonicalBytesAfterValidation(leaf, s.cfg.Receivers, s.cfg.Validators)
	if err != nil {
		return nil, err
	}
	return s.publishComponentPayloadV2(ctx, payload)
}

func (s *cvAPDBNetworkServiceV2) PublishBuiltComponentV2(
	ctx context.Context, material *cvBuiltLeafMaterialV2,
) (*cvComponentRefV2, error) {
	if s == nil || ctx == nil || material == nil || material.owner != s || material.leaf == nil ||
		len(material.wire) == 0 || len(material.wire) > s.cfg.MaximumPayload || s.cfg.LeafContext == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) || material.leaf.DealerID != s.cfg.LocalNode ||
		!bytes.Equal(material.leaf.Digest, hashBytes([]byte(cvLeafDigestDomainV2), material.wire)) {
		return nil, fmt.Errorf("invalid built CV V2 component publication input")
	}
	return s.publishComponentPayloadV2(ctx, material.wire)
}

func (s *cvAPDBNetworkServiceV2) publishComponentPayloadV2(
	ctx context.Context, payload []byte,
) (*cvComponentRefV2, error) {
	instance, err := cvComponentInstanceDigestV2(s.cfg.ExpectedContext, s.cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	shardBytes := s.cfg.ShardBytes
	s.mu.Unlock()
	encoded, err := cvAPDBEncodeSizedV2(
		instance, payload, s.cfg.DataShards, s.cfg.TotalShards, shardBytes, s.cfg.MaximumPayload,
	)
	if err != nil {
		return nil, err
	}
	lock, err := s.Lock(ctx, encoded)
	if err != nil {
		return nil, err
	}
	s.cacheDealerPayloadV2(instance, payload)
	header := cvComponentHeaderV2{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), DealerID: s.cfg.LocalNode,
		PayloadDigest: cvComponentPayloadDigestV2(payload), Instance: append([]byte(nil), instance...), Root: append([]byte(nil), lock.Root...),
	}
	ref := &cvComponentRefV2{Header: header, Lock: *lock}
	if err := cvValidateComponentRefV2(*ref, s.apdbSigner); err != nil {
		return nil, err
	}
	wire, err := cvComponentRefV2CanonicalBytes(*ref)
	if err != nil {
		return nil, err
	}
	s.storeComponentRefV2(*ref)
	s.mu.Lock()
	s.localComponentRefV2 = append([]byte(nil), wire...)
	s.mu.Unlock()
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode {
			_ = s.send(member, cvTagComponentRefV2, wire)
		}
	}
	return ref, nil
}

// AwaitVerifiedComponentCatalogV2 freezes the first dealer-ordered set of L
// components whose complete APDB payloads pass the unique V2 APVSS verifier.
func (s *cvAPDBNetworkServiceV2) AwaitVerifiedComponentCatalogV2(
	ctx context.Context,
) ([]cvComponentRefV2, error) {
	if s == nil || ctx == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 verified component catalog caller")
	}
	s.verifiedCatalogMu.Lock()
	defer s.verifiedCatalogMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.verifiedCatalogV2) == s.cfg.Params.poolSize {
			catalog := cloneComponentRefsV2(s.verifiedCatalogV2)
			s.mu.Unlock()
			return catalog, nil
		}
		verifiedCount := len(s.verifiedComponentsV2)
		candidates := make([]cvComponentRefV2, 0, len(s.componentRefsV2))
		for dealer, ref := range s.componentRefsV2 {
			if _, verified := s.verifiedComponentsV2[dealer]; verified {
				continue
			}
			if _, rejected := s.rejectedComponentsV2[dealer]; rejected {
				continue
			}
			candidates = append(candidates, ref)
		}
		updates := s.componentRefUpdatesV2
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
		results := s.recoverAndVerifyComponentPipelineV2(ctx, candidates)
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
				if _, rejected := s.rejectedComponentsV2[dealer]; !rejected {
					newRejection = true
				}
				s.rejectedComponentsV2[dealer] = struct{}{}
				if newRejection {
					s.experimentMu.Lock()
					s.experimentMetrics.proposerRejectedCount++
					s.experimentMu.Unlock()
				}
			} else if len(s.verifiedCatalogV2) == 0 {
				s.storeVerifiedComponentLockedV2(result.ref, result.leafDigest, result.payload, result.leaf)
			}
			s.mu.Unlock()
		}
		s.mu.Lock()
		if len(s.verifiedCatalogV2) == 0 && len(s.verifiedComponentsV2) >= s.cfg.Params.poolSize {
			dealers := make([]int, 0, len(s.verifiedComponentsV2))
			for dealer := range s.verifiedComponentsV2 {
				dealers = append(dealers, dealer)
			}
			sort.Ints(dealers)
			for _, dealer := range dealers[:s.cfg.Params.poolSize] {
				s.verifiedCatalogV2 = append(s.verifiedCatalogV2, cloneComponentRefV2(s.verifiedComponentsV2[dealer].ref))
			}
		}
		catalogReady := len(s.verifiedCatalogV2) == s.cfg.Params.poolSize
		catalog := cloneComponentRefsV2(s.verifiedCatalogV2)
		s.mu.Unlock()
		if catalogReady {
			return catalog, nil
		}
		if recoveryErr != nil {
			return nil, recoveryErr
		}
	}
}

func (s *cvAPDBNetworkServiceV2) recoverComponentPayloadV2(
	ctx context.Context, ref cvComponentRefV2,
) cvComponentVerificationResultV2 {
	result := cvComponentVerificationResultV2{ref: cloneComponentRefV2(ref)}
	payload, hints, err := s.recoveredComponentPayloadV2(ctx, ref, cvRecoveryProposerCatalogV2)
	if err != nil {
		result.recoverErr = fmt.Errorf("recover CV V2 component %d: %w", ref.Header.DealerID, err)
		return result
	}
	// recoveredComponentPayloadV2 only returns payloads that are already bound
	// to ref.Header.PayloadDigest. Its cache entries are immutable, and the leaf
	// decoder is read-only; the verified catalog takes its own copy on accept.
	result.payload = payload
	result.payloadHints = hints
	return result
}

func (s *cvAPDBNetworkServiceV2) verifyRecoveredComponentV2(
	result cvComponentVerificationResultV2,
) cvComponentVerificationResultV2 {
	if result.recoverErr != nil || result.verifyErr != nil {
		return result
	}
	ref := result.ref
	payload := result.payload
	leaf, err := cvDecodeLeafV2WithHints(
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

// recoverAndVerifyComponentPipelineV2 keeps network recovery ahead of a fixed
// verifier pool. Each recovered payload flows directly to a verifier instead
// of waiting for a complete verification batch.
func (s *cvAPDBNetworkServiceV2) recoverAndVerifyComponentPipelineV2(
	ctx context.Context, refs []cvComponentRefV2,
) []cvComponentVerificationResultV2 {
	if len(refs) == 0 {
		return nil
	}
	recoveryWorkers := cvComponentRecoveryWorkers(len(refs))
	verificationWorkers := cvLeafVerifyWorkers(len(refs))
	results, verificationLatency := cvRunComponentPipelineV2(
		refs, recoveryWorkers, verificationWorkers,
		func(ref cvComponentRefV2) cvComponentVerificationResultV2 {
			return s.recoverComponentPayloadV2(ctx, ref)
		},
		func(result cvComponentVerificationResultV2) cvComponentVerificationResultV2 {
			return s.verifyRecoveredComponentV2(result)
		},
	)
	if verificationLatency > 0 {
		s.experimentMu.Lock()
		s.experimentMetrics.proposerCatalogVerificationLatency += verificationLatency
		s.experimentMu.Unlock()
	}
	return results
}

func cvRunComponentPipelineV2(
	refs []cvComponentRefV2, recoveryWorkers, verificationWorkers int,
	recoverComponent func(cvComponentRefV2) cvComponentVerificationResultV2,
	verifyComponent func(cvComponentVerificationResultV2) cvComponentVerificationResultV2,
) ([]cvComponentVerificationResultV2, time.Duration) {
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

	jobs := make(chan cvComponentPipelineJobV2, recoveryWorkers)
	recovered := make(chan cvComponentPipelineResultV2, verificationWorkers)
	verified := make(chan cvComponentPipelineResultV2, verificationWorkers)
	var recoveryWG sync.WaitGroup
	recoveryWG.Add(recoveryWorkers)
	for range recoveryWorkers {
		go func() {
			defer recoveryWG.Done()
			for job := range jobs {
				recovered <- cvComponentPipelineResultV2{
					index: job.index, result: recoverComponent(job.ref),
				}
			}
		}()
	}
	go func() {
		for index, ref := range refs {
			jobs <- cvComponentPipelineJobV2{index: index, ref: ref}
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
				verified <- cvComponentPipelineResultV2{index: item.index, result: result}
			}
		}()
	}
	go func() {
		verificationWG.Wait()
		close(verified)
	}()

	results := make([]cvComponentVerificationResultV2, len(refs))
	for item := range verified {
		results[item.index] = item.result
	}
	if firstStarted.IsZero() || lastFinished.Before(firstStarted) {
		return results, 0
	}
	return results, lastFinished.Sub(firstStarted)
}

func (s *cvAPDBNetworkServiceV2) verifiedComponentLeafV2(
	ctx context.Context, ref cvComponentRefV2, purpose cvRecoveryPurposeV2,
) (*cvLeafV2, error) {
	dealer := ref.Header.DealerID
	s.mu.Lock()
	if entry, ok := s.verifiedComponentsV2[dealer]; ok {
		if entry.leaf == nil || !equalComponentRefsV2(entry.ref, ref) ||
			!bytes.Equal(entry.leaf.Digest, entry.leafDigest) {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 verified component cache conflict for dealer %d", dealer)
		}
		leaf := entry.leaf
		s.mu.Unlock()
		return leaf, nil
	}
	if call := s.verifiedComponentCalls[dealer]; call != nil {
		if !equalComponentRefsV2(call.ref, ref) {
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
	call := &cvVerifiedComponentCallV2{ref: cloneComponentRefV2(ref), done: make(chan struct{})}
	s.verifiedComponentCalls[dealer] = call
	s.mu.Unlock()

	payload, hints, err := s.recoveredComponentPayloadV2(ctx, ref, purpose)
	var leaf *cvLeafV2
	if err == nil {
		leaf, err = cvDecodeLeafV2WithHints(
			payload, hints, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators,
		)
		if err == nil && leaf.DealerID != dealer {
			err = fmt.Errorf("CV V2 component dealer mismatch: leaf=%d ref=%d", leaf.DealerID, dealer)
		}
	}

	s.mu.Lock()
	if err == nil {
		s.storeVerifiedComponentLockedV2(ref, leaf.Digest, payload, leaf)
	}
	call.leaf = leaf
	call.err = err
	delete(s.verifiedComponentCalls, dealer)
	close(call.done)
	s.mu.Unlock()
	return leaf, err
}

// storeVerifiedComponentLockedV2 transfers an authenticated, fully decoded
// payload into the immutable verified cache. The caller must hold s.mu and
// must not mutate payload or leaf after the transfer.
func (s *cvAPDBNetworkServiceV2) storeVerifiedComponentLockedV2(
	ref cvComponentRefV2, leafDigest, payload []byte, leaf *cvLeafV2,
) {
	if s.verifiedComponentsV2 == nil {
		s.verifiedComponentsV2 = make(map[int]cvVerifiedComponentV2)
	}
	s.verifiedComponentsV2[ref.Header.DealerID] = cvVerifiedComponentV2{
		ref: cloneComponentRefV2(ref), leafDigest: append([]byte(nil), leafDigest...),
		payload: payload, leaf: leaf,
	}
	// The verified entry is checked first by recoveredComponentPayloadV2, so
	// its earlier recovery payload and decode hints are now redundant.
	delete(s.recoveredPayloadsV2, cvRecoveredComponentPayloadKeyV2(ref))
}

func (s *cvAPDBNetworkServiceV2) VerifiedComponentLeavesV2(
	pool *cvPoolV2, selected []int,
) ([]*cvLeafV2, error) {
	if s == nil || pool == nil || len(selected) != s.cfg.Params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 verified component selection")
	}
	leaves := make([]*cvLeafV2, len(selected))
	seen := make(map[int]struct{}, len(selected))
	if _, err := cvPoolV2CanonicalBytes(pool, s.cfg.Params); err != nil {
		return nil, fmt.Errorf("invalid CV V2 verified component Pool: %w", err)
	}
	s.mu.Lock()
	if len(s.verifiedCatalogV2) != s.cfg.Params.poolSize || len(pool.Components) != len(s.verifiedCatalogV2) {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 Pool does not match frozen verified catalog")
	}
	for i := range s.verifiedCatalogV2 {
		if !equalComponentRefsV2(s.verifiedCatalogV2[i], pool.Components[i]) {
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
		entry, ok := s.verifiedComponentsV2[ref.Header.DealerID]
		if !ok || !equalComponentRefsV2(entry.ref, ref) {
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

func (s *cvAPDBNetworkServiceV2) storeComponentRefV2(ref cvComponentRefV2) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.componentRefsV2[ref.Header.DealerID]; exists {
		return false
	}
	s.componentRefsV2[ref.Header.DealerID] = ref
	cvNotifyAPDBV2(s.componentRefUpdatesV2)
	return true
}

func cloneComponentRefV2(ref cvComponentRefV2) cvComponentRefV2 {
	return cvComponentRefV2{
		Header: cvComponentHeaderV2{
			ContextDigest: append([]byte(nil), ref.Header.ContextDigest...), DealerID: ref.Header.DealerID,
			PayloadDigest: append([]byte(nil), ref.Header.PayloadDigest...),
			Instance:      append([]byte(nil), ref.Header.Instance...), Root: append([]byte(nil), ref.Header.Root...),
		},
		Lock: cvAPDBLockV2{
			InstanceDigest: append([]byte(nil), ref.Lock.InstanceDigest...), Root: append([]byte(nil), ref.Lock.Root...),
			Certificate: append([]byte(nil), ref.Lock.Certificate...),
		},
	}
}

func cloneComponentRefsV2(refs []cvComponentRefV2) []cvComponentRefV2 {
	cloned := make([]cvComponentRefV2, len(refs))
	for i := range refs {
		cloned[i] = cloneComponentRefV2(refs[i])
	}
	return cloned
}

func equalComponentRefsV2(left, right cvComponentRefV2) bool {
	leftWire, leftErr := cvComponentRefV2CanonicalBytes(left)
	rightWire, rightErr := cvComponentRefV2CanonicalBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func (s *cvAPDBNetworkServiceV2) handleComponentRefV2(msg Message) {
	// The authenticated transport already binds msg.From to the dealer. Once
	// that dealer's reference is known, duplicate announcements need no decode;
	// the existing path also ignored replacement wires for known dealers.
	s.mu.Lock()
	knownDealer := false
	if _, ok := s.componentRefsV2[msg.From]; ok {
		knownDealer = true
	}
	s.mu.Unlock()
	if knownDealer {
		return
	}
	ref, err := cvDecodeComponentRefV2(msg.Body)
	if err != nil || ref.Header.DealerID != msg.From || !bytes.Equal(ref.Header.ContextDigest, s.cfg.ExpectedContext) {
		return
	}
	if err := cvValidateComponentRefV2(ref, s.apdbSigner); err != nil {
		return
	}
	if !s.storeComponentRefV2(ref) {
		return
	}
	s.mu.Lock()
	localWire := append([]byte(nil), s.localComponentRefV2...)
	s.mu.Unlock()
	if len(localWire) != 0 && msg.From != s.cfg.LocalNode {
		_ = s.send(msg.From, cvTagComponentRefV2, localWire)
	}
}
