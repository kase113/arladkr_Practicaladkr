package core

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type cvProposerSlotRunnerV2 func(context.Context, int) error

type cvProposerSlotResultV2 struct {
	proposer int
	err      error
}

func cvSampledProposerSlotGraceV2(proposerSampleSize int) time.Duration {
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
	return cvSampledProposerSlotGraceV2(proposerSampleSize)
}

func cvRunSampledProposerSlotsV2(
	ctx context.Context,
	proposers []int,
	candidates <-chan *cvAgreementObjectV2,
	run cvProposerSlotRunnerV2,
) (*cvAgreementObjectV2, error) {
	if ctx == nil || len(proposers) == 0 || candidates == nil || run == nil ||
		len(sortedUnique(proposers)) != len(proposers) {
		return nil, fmt.Errorf("invalid CV V2 sampled proposer slots")
	}
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan cvProposerSlotResultV2, len(proposers))
	launch := func(proposer int) {
		go func() {
			results <- cvProposerSlotResultV2{proposer: proposer, err: run(pipelineCtx, proposer)}
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
		if primaryGrace := cvSampledProposerSlotGraceV2(len(proposers)); primaryGrace <= 0 {
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

func runCVProposerSlotV2(
	ctx context.Context, cfg Config, runtime *cvEpochRuntimeV2, service *cvAPDBNetworkServiceV2,
	localOld, proposer int, contextDigest []byte, shardBytes int,
) error {
	if ctx == nil || runtime == nil || service == nil || !cvContainsID(runtime.context.OldRoster, proposer) {
		return fmt.Errorf("invalid CV V2 proposer slot")
	}
	var pool *cvPoolV2
	var poolCert *cvPoolCertificateV2
	var err error
	if localOld == proposer {
		refs, waitErr := service.AwaitVerifiedComponentCatalogV2(ctx)
		if waitErr != nil {
			return waitErr
		}
		pool, err = cvBuildPoolV2(contextDigest, proposer, refs, runtime.params)
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
	selected, err := cvSelectedPoolIndicesV2(runtime.params.poolSize, runtime.params.componentCount, contributorCoin.Value)
	if err != nil {
		return err
	}

	var request *cvValidationRequestV2
	var vCert *cvValidationCertificateV2
	if localOld == proposer {
		leaves, selectedErr := service.VerifiedComponentLeavesV2(pool, selected)
		if selectedErr != nil {
			return selectedErr
		}
		aggregate, aggregateErr := cvAggVerifiedV2(leaves, runtime.context, runtime.params)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregatePayload, aggregateErr := cvAggregateV2CanonicalBytesAfterValidation(
			aggregate, runtime.context, runtime.params,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		selectionDigest, aggregateErr := cvSelectionDigestV2(
			contributorCoin, selected, runtime.params.poolSize, runtime.params.componentCount,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateInstance, aggregateErr := cvAggregateInstanceDigestV2(contextDigest, proposer, pool.Digest, selectionDigest)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateEncoded, aggregateErr := cvAPDBEncodeSizedV2(
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
		if aggregateErr = service.rememberVerifiedAggregatePayloadV2(aggregateInstance, arc.Root, aggregatePayload); aggregateErr != nil {
			return aggregateErr
		}
		payloadDigest, aggregateErr := cvAggregatePayloadDigestV2(aggregatePayload)
		if aggregateErr != nil {
			return aggregateErr
		}
		header := cvAggregateHeaderV2{
			ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
			SelectionDigest: selectionDigest, AggregateDigest: append([]byte(nil), aggregate.Digest...),
			PayloadDigest: payloadDigest, APDBInstance: aggregateInstance, APDBRoot: append([]byte(nil), arc.Root...),
		}
		request = &cvValidationRequestV2{
			Header: header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *contributorCoin,
			SelectedIndices: selected, ARC: *arc,
		}
		vCert, err = service.CertifyAggregate(ctx, request)
	} else {
		request, vCert, err = service.AwaitCertifiedValidationV2(ctx, proposer)
	}
	if err != nil {
		return fmt.Errorf("certify CV V2 proposer %d aggregate: %w", proposer, err)
	}
	candidate := &cvAgreementObjectV2{
		Header: request.Header, Pool: request.Pool, PoolCert: request.PoolCert,
		ContributorCoin: request.ContributorCoin, SelectedIndices: append([]int(nil), request.SelectedIndices...),
		VCert: *vCert, ARC: request.ARC,
	}
	return service.publishLocallyCertifiedCandidateV2(ctx, candidate)
}
