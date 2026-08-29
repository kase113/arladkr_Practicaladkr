package core

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type cvProposerSlotRunnerScalar func(context.Context, int) error

type cvProposerSlotResultScalar struct {
	proposer int
	err      error
}

func cvSampledProposerSlotGraceScalar(proposerSampleSize int) time.Duration {
	if raw := strings.TrimSpace(os.Getenv("RLADKR_CV_PROPOSER_SLOT_GRACE_MS")); raw != "" {
		milliseconds, err := strconv.Atoi(raw)
		if err == nil && milliseconds >= 0 {
			return time.Duration(milliseconds) * time.Millisecond
		}
	}
	// Staging reduced both latency and bytes at kappa=6. At kappa>=11 the
	// primary catalog exceeded the grace and the delayed backup wave regressed
	// quorum latency, so larger samples retain the concurrent path.
	if proposerSampleSize > 6 {
		return 0
	}
	return cvAggregatePrimaryGrace()
}

func CVSampledProposerSlotGrace(proposerSampleSize int) time.Duration {
	return cvSampledProposerSlotGraceScalar(proposerSampleSize)
}

func cvRunSampledProposerSlotsScalar(
	ctx context.Context,
	proposers []int,
	candidates <-chan *cvAgreementObjectScalar,
	run cvProposerSlotRunnerScalar,
) (*cvAgreementObjectScalar, error) {
	if ctx == nil || len(proposers) == 0 || candidates == nil || run == nil ||
		len(sortedUnique(proposers)) != len(proposers) {
		return nil, fmt.Errorf("invalid CV V2 sampled proposer slots")
	}
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan cvProposerSlotResultScalar, len(proposers))
	launch := func(proposer int) {
		go func() {
			results <- cvProposerSlotResultScalar{proposer: proposer, err: run(pipelineCtx, proposer)}
		}()
	}
	launch(proposers[0])

	backupsLaunched := len(proposers) == 1
	var graceTimer *time.Timer
	var grace <-chan time.Time
	launchBackups := func() {
		if backupsLaunched {
			return
		}
		backupsLaunched = true
		for _, proposer := range proposers[1:] {
			launch(proposer)
		}
		if graceTimer != nil {
			if !graceTimer.Stop() {
				select {
				case <-graceTimer.C:
				default:
				}
			}
			grace = nil
		}
	}
	if !backupsLaunched {
		if primaryGrace := cvSampledProposerSlotGraceScalar(len(proposers)); primaryGrace <= 0 {
			launchBackups()
		} else {
			graceTimer = time.NewTimer(primaryGrace)
			grace = graceTimer.C
			defer graceTimer.Stop()
		}
	}

	failed := make(map[int]error, len(proposers))
	for {
		if backupsLaunched && len(failed) == len(proposers) {
			select {
			case candidate, ok := <-candidates:
				if ok && candidate != nil {
					return candidate, nil
				}
			default:
			}
			return nil, fmt.Errorf("all sampled CV V2 proposer slots failed")
		}
		select {
		case candidate, ok := <-candidates:
			if !ok || candidate == nil {
				return nil, fmt.Errorf("invalid CV V2 certified candidate channel")
			}
			return candidate, nil
		case result := <-results:
			failed[result.proposer] = result.err
			if result.proposer == proposers[0] {
				// A failed primary cannot benefit from the optimistic grace.
				launchBackups()
			}
		case <-grace:
			launchBackups()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func runCVProposerSlotScalar(
	ctx context.Context, cfg Config, runtime *cvEpochRuntimeScalar, service *cvAPDBNetworkServiceScalar,
	localOld, proposer int, contextDigest []byte, shardBytes int,
) error {
	if ctx == nil || runtime == nil || service == nil || !cvContainsID(runtime.context.OldRoster, proposer) {
		return fmt.Errorf("invalid CV V2 proposer slot")
	}
	var pool *cvPoolScalar
	var poolCert *cvPoolCertificateScalar
	var err error
	if localOld == proposer {
		refs, waitErr := service.AwaitVerifiedComponentCatalogScalar(ctx)
		if waitErr != nil {
			return waitErr
		}
		pool, err = cvBuildPoolScalar(contextDigest, proposer, refs, runtime.params)
		if err == nil {
			poolCert, err = service.CertifyPool(ctx, pool)
		}
	} else {
		pool, poolCert, err = service.AwaitCertifiedPool(ctx, proposer)
	}
	if err != nil {
		return fmt.Errorf("certify CV V2 proposer %d Pool: %w", proposer, err)
	}
	contributorCoin, err := service.ContributorCoin(ctx, pool, poolCert)
	if err != nil {
		return fmt.Errorf("collect CV V2 proposer %d contributor coin: %w", proposer, err)
	}
	selected, err := cvSelectedPoolIndicesScalar(runtime.params.poolSize, runtime.params.componentCount, contributorCoin.Value)
	if err != nil {
		return err
	}

	var request *cvValidationRequestScalar
	var vCert *cvValidationCertificateScalar
	if localOld == proposer {
		leaves, selectedErr := service.VerifiedComponentLeavesScalar(pool, selected)
		if selectedErr != nil {
			return selectedErr
		}
		aggregate, aggregateErr := cvAggVerifiedScalar(leaves, runtime.context, runtime.params)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregatePayload, aggregateErr := cvAggregateScalarCanonicalBytesAfterValidation(
			aggregate, runtime.context, runtime.params,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		selectionDigest, aggregateErr := cvSelectionDigestScalar(
			contributorCoin, selected, runtime.params.poolSize, runtime.params.componentCount,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateInstance, aggregateErr := cvAggregateInstanceDigestScalar(contextDigest, proposer, pool.Digest, selectionDigest)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateEncoded, aggregateErr := cvAPDBEncodeSizedScalar(
			aggregateInstance, aggregatePayload, runtime.params.recoveryThreshold,
			len(cfg.OldCommittee), shardBytes, cvMaxLeafWireBytes,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		arc, aggregateErr := service.LockAggregate(ctx, aggregateEncoded)
		if aggregateErr != nil {
			return aggregateErr
		}
		if aggregateErr = service.rememberVerifiedAggregatePayloadScalar(aggregateInstance, arc.Root, aggregatePayload); aggregateErr != nil {
			return aggregateErr
		}
		payloadDigest, aggregateErr := cvAggregatePayloadDigestScalar(aggregatePayload)
		if aggregateErr != nil {
			return aggregateErr
		}
		header := cvAggregateHeaderScalar{
			ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
			SelectionDigest: selectionDigest, AggregateDigest: append([]byte(nil), aggregate.Digest...),
			PayloadDigest: payloadDigest, APDBInstance: aggregateInstance, APDBRoot: append([]byte(nil), arc.Root...),
		}
		request = &cvValidationRequestScalar{
			Header: header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *contributorCoin,
			SelectedIndices: selected, ARC: *arc,
		}
		vCert, err = service.CertifyAggregate(ctx, request)
	} else {
		request, vCert, err = service.AwaitCertifiedValidationScalar(ctx, proposer)
	}
	if err != nil {
		return fmt.Errorf("certify CV V2 proposer %d aggregate: %w", proposer, err)
	}
	candidate := &cvAgreementObjectScalar{
		Header: request.Header, Pool: request.Pool, PoolCert: request.PoolCert,
		ContributorCoin: request.ContributorCoin, SelectedIndices: append([]int(nil), request.SelectedIndices...),
		VCert: *vCert, ARC: request.ARC,
	}
	return service.publishLocallyCertifiedCandidateScalar(ctx, candidate)
}
