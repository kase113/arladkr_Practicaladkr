package core

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// RunCVEpochV2 composes the scalar/group V2 network stages.
func RunCVEpochV2(ctx context.Context, cfg Config) (*EpochResult, error) {
	started := time.Now()
	c := NormalizeConfig(cfg)
	if ctx == nil {
		return nil, fmt.Errorf("nil CV V2 epoch context")
	}
	if err := validateCVEpochConfig(c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		c.runtime = newRuntimeCommMetrics(c.CommMetrics)
	}
	transport := c.protocolTransport
	ownedTransport := false
	if transport == nil {
		nodes := sortedUnique(append(append([]int(nil), c.OldCommittee...), c.NewCommittee...))
		var transportErr error
		transport, transportErr = newAgreementTransport(c, nodes, len(nodes)*256)
		if transportErr != nil {
			return nil, transportErr
		}
		ownedTransport = true
	}
	if ownedTransport {
		defer transport.Close()
	}
	runtime := c.cvRuntimeV2
	if runtime == nil {
		var err error
		runtime, err = cvLoadEpochRuntimeV2(c)
		if err != nil {
			return nil, err
		}
	}
	localOld := c.LocalNodeIDs[0]
	localReceiver := c.CVLocalReceiverIDs[0]
	contextDigest, err := cvLeafContextDigestV2(runtime.context)
	if err != nil {
		return nil, err
	}
	shardBytes, err := cvEpochShardBytesUpperBoundV2(
		runtime.context, runtime.params, runtime.receivers, runtime.validators, runtime.params.recoveryThreshold,
	)
	if err != nil {
		return nil, err
	}

	router, err := newCVSAPVSSRouterWithReceivers(
		ctx, transport, c.SID, c.Epoch, c.OldCommittee, c.NewCommittee,
		[]int{localOld, localReceiver}, (len(c.OldCommittee)+len(c.NewCommittee))*256, runtime.authenticator,
	)
	if err != nil {
		return nil, err
	}
	defer router.Close()
	holderStore, err := newCVAPDBHolderStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	decisionStore, err := newCVDecisionSignStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	scalarStore, err := newCVScalarStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	baseServiceCfg := cvAPDBNetworkServiceConfigV2{
		SID: c.SID, Epoch: uint64(c.Epoch), OldRoster: c.OldCommittee, NewRoster: c.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(c.OldCommittee),
		DataShards: runtime.params.recoveryThreshold, ShardBytes: shardBytes, MaximumPayload: cvMaxLeafWireBytes,
		Params: runtime.params, LeafContext: runtime.context, Receivers: runtime.receivers, Validators: runtime.validators,
	}
	oldCfg := baseServiceCfg
	oldCfg.LocalNode = localOld
	oldCfg.Receivers = cvPublicReceiverMaterialV2(runtime.receivers)
	oldCfg.DecisionStore = decisionStore
	oldService, err := newCVAPDBNetworkServiceV2(ctx, oldCfg, transport, router, runtime.authenticator,
		holderStore, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer oldService.Close()
	receiverCfg := baseServiceCfg
	receiverCfg.LocalNode = localReceiver
	receiverCfg.Validators = cvPublicValidatorMaterialV2(runtime.validators)
	receiverCfg.ScalarStore = scalarStore
	receiverService, err := newCVAPDBNetworkServiceV2(ctx, receiverCfg, transport, router, runtime.authenticator,
		nil, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer receiverService.Close()

	c.runtime.setCommPhase("component_disperse")
	leafStarted := time.Now()
	leafMaterial, err := oldService.BuildLeafMaterialV2(ctx)
	if err != nil {
		return nil, fmt.Errorf("build CV V2 quorum/fallback leaf: %w", err)
	}
	leaf := leafMaterial.leaf
	leafLatency := time.Since(leafStarted)
	ackCount, fallbackCount, proofBytes, leafWireBytes, err := cvLeafExperimentMetricsFromWireV2(
		leaf, leafMaterial.wire, runtime.context,
	)
	if err != nil {
		return nil, err
	}
	componentStarted := time.Now()
	if _, err := oldService.PublishBuiltComponentV2(ctx, leafMaterial); err != nil {
		return nil, fmt.Errorf("publish CV V2 component: %w", err)
	}
	componentLatency := time.Since(componentStarted)

	c.runtime.setCommPhase("candidate_formation")
	coinStarted := time.Now()
	eligibilityCoin, err := oldService.EligibilityCoin(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect CV V2 eligibility coin: %w", err)
	}
	eligibilityCoinLatency := time.Since(coinStarted)
	proposers, validatorSample, err := cvDeriveEligibilitySamplesV2(
		c.OldCommittee, eligibilityCoin.Value, runtime.params.proposerSampleSize, runtime.params.validatorSampleSize,
	)
	if err != nil || len(proposers) == 0 {
		return nil, fmt.Errorf("derive CV V2 eligibility samples: %w", err)
	}
	public := cvAgreementPublicContextV2{SID: c.SID, Epoch: uint64(c.Epoch), ContextDigest: contextDigest,
		OldCommittee: c.OldCommittee, EligibilityCoin: eligibilityCoin, Params: runtime.params,
		APDBSigner: runtime.apdbSigner, ControlSigner: runtime.controlSigner, CoinSigner: runtime.coinSigner,
		ValidatorKeys: runtime.validators}
	proposerSlotsStarted := time.Now()
	candidate, err := cvRunSampledProposerSlotsV2(
		ctx, proposers, oldService.certifiedCandidateChV2,
		func(slotCtx context.Context, proposer int) error {
			return runCVProposerSlotV2(
				slotCtx, c, runtime, oldService, localOld, proposer, contextDigest, shardBytes,
			)
		},
	)
	if err != nil {
		return nil, err
	}
	proposerSlotsLatency := time.Since(proposerSlotsStarted)
	candidateFormationLatency := time.Since(coinStarted)
	c.runtime.setCommPhase("aggregate_agreement")
	agreementStarted := time.Now()
	decided, agreementWire, peerWait, err := cvRunAgreementV2(ctx, c, candidate, public)
	if err != nil {
		return nil, fmt.Errorf("run CV V2 agreement: %w", err)
	}
	agreementLatency := time.Since(agreementStarted)
	pool := &decided.Pool
	selected := append([]int(nil), decided.SelectedIndices...)
	c.runtime.setCommPhase("receipt")
	handoffStarted := time.Now()
	handoff, err := oldService.FinalizeDecision(ctx, decided)
	if err != nil {
		return nil, fmt.Errorf("finalize CV V2 decision: %w", err)
	}
	accepted, err := receiverService.AwaitHandoff(ctx)
	if err != nil {
		return nil, fmt.Errorf("await CV V2 handoff: %w", err)
	}
	if !bytes.Equal(accepted.Header.AggregateDigest, handoff.Header.AggregateDigest) {
		return nil, fmt.Errorf("CV V2 local receiver accepted a different handoff")
	}
	handoffLatency := time.Since(handoffStarted)
	c.runtime.setCommPhase("recover_shard")
	recoveryStarted := time.Now()
	aggregate, scalar, output, publicKey, err := receiverService.RecoverAndExchangeScalarShare(ctx, accepted)
	if err != nil {
		return nil, fmt.Errorf("recover CV V2 aggregate share: %w", err)
	}
	aggregateWire, err := cvAggregateV2CanonicalBytesAfterValidation(aggregate, runtime.context, runtime.params)
	if err != nil {
		return nil, err
	}
	shareWire, err := cvScalarShareOutputV2CanonicalBytes(output)
	if err != nil {
		return nil, err
	}
	scalarBytes := scalar.Bytes()
	publicKeyBytes := publicKey.Bytes()
	serviceGraceStarted := time.Now()
	serviceGrace := cvRecoverServiceGraceV2(c.RouteSendTimeout)
	// The linger keeps every responder alive, which includes decision-share
	// replies for peers still inside FinalizeDecision. RLADKR_DECISION_
	// RESPONDER_GRACE_MS can widen that window on deployments whose
	// finalization stragglers outlive the recover grace; the linger stays
	// excluded from reported latency either way. Failure paths never reach
	// this point, so only successful nodes linger.
	if decisionGrace := cvDecisionResponderGraceV2(); decisionGrace > serviceGrace {
		serviceGrace = decisionGrace
	}
	graceTimer := time.NewTimer(serviceGrace)
	select {
	case <-ctx.Done():
	case <-graceTimer.C:
	}
	if !graceTimer.Stop() {
		select {
		case <-graceTimer.C:
		default:
		}
	}
	serviceGraceLatency := time.Since(serviceGraceStarted)
	agreementDigest := hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/agreement-result"), agreementWire)
	selectedDealers := make([]int, len(selected))
	for i, index := range selected {
		selectedDealers[i] = pool.Components[index].Header.DealerID
	}
	sampling, err := ResolveCVV2Sampling(
		len(c.OldCommittee), c.OldFaults, c.CVSamplingFailureTarget,
		runtime.params.proposerSampleSize, runtime.params.validatorSampleSize,
	)
	if err != nil {
		return nil, err
	}
	costMetrics, err := cvCalculateEpochCostMetricsV2(
		decided, handoff, agreementWire, aggregateWire, runtime.params, validatorSample,
		oldService.CertifiedCandidateCountV2(), len(c.OldCommittee)*shardBytes,
	)
	if err != nil {
		return nil, err
	}
	totalSent, totalRecv := c.runtime.commStats()
	phaseSent, phaseRecv := c.runtime.phaseCommStats()
	experimentMetrics := oldService.experimentMetricsV2()
	receiverExperimentMetrics := receiverService.experimentMetricsV2()
	cvAddCostBreakdownV2(phaseSent, phaseRecv, experimentMetrics, receiverExperimentMetrics)
	// proposer slots share one runtime and can overwrite commPhase while they
	// run concurrently. Preserve that raw window counter separately, and make
	// candidate_formation tag-accurate for benchmark consumers.
	phaseSent["candidate_phase_counter"] = phaseSent["candidate_formation"]
	phaseRecv["candidate_phase_counter"] = phaseRecv["candidate_formation"]
	if candidateBytes, ok := phaseSent["candidate_relay"]; ok {
		phaseSent["candidate_formation"] = candidateBytes
	}
	if candidateBytes, ok := phaseRecv["candidate_relay"]; ok {
		phaseRecv["candidate_formation"] = candidateBytes
	}
	return &EpochResult{
		AgreementMode: "single-mvba-v2", AblationMode: c.AblationMode, CVAPVSSMode: cvSAPVSSV2ProtocolVersion,
		LockedSet: append([]int(nil), poolDealerIDsV2(pool)...), SampledSet: selectedDealers, AggRLODealers: selectedDealers,
		RecoveredAggregate: aggregateWire, AggRLODigest: agreementDigest, RecoverAggSuccess: true,
		NewShares:    map[int][]byte{localReceiver: append([]byte(nil), scalarBytes[:]...)},
		NewPublicKey: append([]byte(nil), publicKeyBytes[:]...), CVReceipts: map[int][]byte{localReceiver: shareWire},
		CVComponentCount: runtime.params.poolSize, CVARCHolderCount: runtime.params.apdbLockThreshold,
		CVRecoveredShardCount: runtime.params.recoveryThreshold, CVVerifiedReceiptCount: runtime.params.newShareThreshold,
		CVSampling:         sampling,
		CVLeafBuildLatency: leafLatency, CVComponentDisperseLatency: componentLatency,
		CVComponentCollectionLatency:      candidateFormationLatency,
		CVEligibilityCoinLatency:          eligibilityCoinLatency,
		CVProposerSlotsLatency:            proposerSlotsLatency,
		CVCoinFanoutLatency:               experimentMetrics.coinFanoutLatency,
		CVCandidateFanoutACKWaitLatency:   experimentMetrics.candidateFanoutACKWaitLatency,
		CVCandidateFanoutRetryWaitLatency: experimentMetrics.candidateFanoutRetryWaitLatency,
		CVCandidateFanoutMaxPeerLatency:   experimentMetrics.candidateFanoutMaxPeerLatency,
		CVCandidateFanoutAttempts:         experimentMetrics.candidateFanoutAttempts,
		CVCandidateFanoutRetries:          experimentMetrics.candidateFanoutRetries,
		CVAggregateAgreementLatency:       agreementLatency, MVBAPeerWaitLatency: peerWait,
		CVRecoverShardLatency: time.Since(recoveryStarted), CVReceiptLatency: handoffLatency,
		CVAPVSSACKCount: ackCount, CVAPVSSFallbackCount: fallbackCount,
		CVAPVSSProofBytes: proofBytes, CVAPVSSLeafWireBytes: leafWireBytes,
		CVCompletedCandidateCount:               costMetrics.completedCandidates,
		CVPoolWireBytes:                         costMetrics.poolBytes,
		CVValidationRequestWireBytes:            costMetrics.validationRequestBytes,
		CVAgreementObjectWireBytes:              costMetrics.agreementObjectBytes,
		CVAggregatePayloadBytes:                 costMetrics.aggregatePayloadBytes,
		CVAggregateAPDBShardBytes:               costMetrics.aggregateAPDBShardBytes,
		CVPoolCertificateBytes:                  costMetrics.poolCertificateBytes,
		CVValidationCertificateBytes:            costMetrics.validationCertificateBytes,
		CVARCCertificateBytes:                   costMetrics.arcCertificateBytes,
		CVDecisionCertificateBytes:              costMetrics.decisionCertificateBytes,
		CVHandoffWireBytes:                      costMetrics.handoffBytes,
		CVProposerRecoverySentBytes:             experimentMetrics.proposerRecoverySentBytes,
		CVProposerRecoveryRecvBytes:             experimentMetrics.proposerRecoveryRecvBytes,
		CVProposerRecoveryLatency:               experimentMetrics.proposerRecoveryLatency,
		CVProposerCatalogVerificationLatency:    experimentMetrics.proposerCatalogVerificationLatency,
		CVProposerCatalogScanCount:              experimentMetrics.proposerCatalogScanCount,
		CVProposerRejectedComponentCount:        experimentMetrics.proposerRejectedCount,
		CVDealerHintBuildLatency:                experimentMetrics.dealerHintBuildLatency,
		CVDealerResponseEncodeLatency:           experimentMetrics.dealerResponseEncodeLatency,
		CVReceiverPayloadValidationLatency:      experimentMetrics.receiverPayloadDecodeLatency,
		CVRecoveryQueueWaitLatency:              experimentMetrics.recoveryQueueWaitLatency,
		CVRecoveryWorkerLatency:                 experimentMetrics.recoveryWorkerLatency,
		CVValidatorComponentRecoverySentBytes:   experimentMetrics.validatorComponentRecoverySentBytes,
		CVValidatorComponentRecoveryRecvBytes:   experimentMetrics.validatorComponentRecoveryRecvBytes,
		CVValidatorComponentRecoveryLatency:     experimentMetrics.validatorComponentRecoveryLatency,
		CVValidatorAggregateRecoverySentBytes:   experimentMetrics.validatorAggregateRecoverySentBytes,
		CVValidatorAggregateRecoveryRecvBytes:   experimentMetrics.validatorAggregateRecoveryRecvBytes,
		CVValidatorAggregateRecoveryLatency:     experimentMetrics.validatorAggregateRecoveryLatency,
		CVNewAggregateRecoveryLatency:           receiverExperimentMetrics.newAggregateRecoveryLatency,
		RecoverServiceGraceLatency:              serviceGraceLatency,
		CVARCFormationLatency:                   experimentMetrics.arcFormationLatency,
		CVAggregateOfferSendLatency:             experimentMetrics.aggregateOfferSendLatency,
		CVValidationCertificateFormationLatency: experimentMetrics.validationCertificateLatency,
		CVValidationCanonicalLatency:            experimentMetrics.validationCanonicalLatency,
		CVValidationNetworkWaitLatency:          experimentMetrics.validationNetworkWaitLatency,
		CVValidationSignatureVerifyLatency:      experimentMetrics.validationSignatureVerifyLatency,
		CVValidationAggregateVerifyLatency:      experimentMetrics.validationAggregateVerifyLatency,
		CVDecisionCertificateFormationLatency:   experimentMetrics.decisionCertificateLatency,
		CVScalarBoundedDLogLatency:              receiverExperimentMetrics.scalarBoundedDLogLatency,
		CVBlindingGroupDecryptionLatency:        receiverExperimentMetrics.blindingGroupDecryptionLatency,
		TotalSentBytes:                          totalSent, TotalRecvBytes: totalRecv, PhaseSentBytes: phaseSent, PhaseRecvBytes: phaseRecv,
		PerNode: []NodeOutput{{NodeID: localOld, DecidedSet: selectedDealers, Latency: time.Since(started)}},
	}, nil
}

func cvRecoverServiceGraceV2(routeSendTimeout time.Duration) time.Duration {
	grace := 2 * routeSendTimeout
	// A route timeout of at least one second is used by the shared
	// multi-node test harness and larger-committee profiles. Keep a wider
	// holder-service window there so CPU scheduling skew cannot close the
	// only shard responders before a slower honest receiver starts recovery.
	if routeSendTimeout >= time.Second && grace < 10*time.Second {
		return 10 * time.Second
	}
	if grace < 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	if grace > 10*time.Second {
		return 10 * time.Second
	}
	return grace
}

func cvAddCostBreakdownV2(sent, recv map[string]uint64, services ...cvServiceExperimentMetricsV2) {
	if sent == nil || recv == nil {
		return
	}
	tagGroups := map[string][]string{
		"arc_share":          {cvTagAggregateARCShareV2},
		"pool_coin":          {cvTagCoinShareV2, cvTagPoolOfferV2, cvTagPoolCertShareV2, cvTagPoolCertV2},
		"validation_request": {cvTagValidationRequestV2, cvTagValidationSignatureV2, cvTagValidationResultV2},
		"candidate_relay":    {cvTagCertifiedCandidateV2, cvTagCertifiedCandidateACKV2, cvTagCertifiedCandidateAnnounceV2, cvTagCertifiedCandidateFetchV2, cvTagCertifiedCandidateResponseV2},
		"decision_handoff":   {cvTagDecisionShareV2, cvTagHandoffV2},
		"new_share_exchange": {cvTagAggregateShareV2},
	}
	for _, metrics := range services {
		sent["component_apdb_dispersal"] += metrics.componentDispersalSentBytes
		recv["component_apdb_dispersal"] += metrics.componentDispersalRecvBytes
		sent["aggregate_apdb_dispersal"] += metrics.aggregateDispersalSentBytes
		recv["aggregate_apdb_dispersal"] += metrics.aggregateDispersalRecvBytes
		sent["new_aggregate_recovery"] += metrics.newAggregateRecoverySentBytes
		recv["new_aggregate_recovery"] += metrics.newAggregateRecoveryRecvBytes
		for name, tags := range tagGroups {
			for _, tag := range tags {
				sent[name] += metrics.tagSentBytes[tag]
				recv[name] += metrics.tagRecvBytes[tag]
			}
		}
	}
}

type cvEpochCostMetricsV2 struct {
	completedCandidates        int
	poolBytes                  int
	validationRequestBytes     int
	agreementObjectBytes       int
	aggregatePayloadBytes      int
	aggregateAPDBShardBytes    int
	poolCertificateBytes       int
	validationCertificateBytes int
	arcCertificateBytes        int
	decisionCertificateBytes   int
	handoffBytes               int
}

func cvCalculateEpochCostMetricsV2(
	decided *cvAgreementObjectV2, handoff *cvHandoffV2, agreementWire, aggregateWire []byte,
	params cvV2Params, validatorSample []int,
	completedCandidates, aggregateAPDBShardBytes int,
) (cvEpochCostMetricsV2, error) {
	if decided == nil || handoff == nil || len(validatorSample) != params.validatorSampleSize || completedCandidates <= 0 ||
		aggregateAPDBShardBytes <= 0 {
		return cvEpochCostMetricsV2{}, fmt.Errorf("invalid CV V2 epoch cost metrics input")
	}
	poolWire, err := cvPoolV2CanonicalBytes(&decided.Pool, params)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	validationWire, err := cvValidationRequestV2CanonicalBytes(&cvValidationRequestV2{
		Header: decided.Header, Pool: decided.Pool, PoolCert: decided.PoolCert,
		ContributorCoin: decided.ContributorCoin, SelectedIndices: decided.SelectedIndices, ARC: decided.ARC,
	}, params)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	poolCertificate, err := cvPoolCertificateV2CanonicalBytes(&decided.PoolCert)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	validationCertificate, err := cvValidationCertificateV2CanonicalBytes(&decided.VCert, validatorSample)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	arc, err := cvAPDBLockV2CanonicalBytes(&decided.ARC)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	handoffWire, err := cvHandoffV2CanonicalBytes(handoff)
	if err != nil {
		return cvEpochCostMetricsV2{}, err
	}
	return cvEpochCostMetricsV2{
		completedCandidates: completedCandidates, poolBytes: len(poolWire),
		validationRequestBytes: len(validationWire), agreementObjectBytes: len(agreementWire),
		aggregatePayloadBytes: len(aggregateWire), aggregateAPDBShardBytes: aggregateAPDBShardBytes,
		poolCertificateBytes: len(poolCertificate), validationCertificateBytes: len(validationCertificate),
		arcCertificateBytes: len(arc), decisionCertificateBytes: len(handoff.DecCert), handoffBytes: len(handoffWire),
	}, nil
}

func cvLeafExperimentMetricsV2(
	leaf *cvLeafV2, context *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (ackCount, fallbackCount, proofBytes, leafWireBytes int, err error) {
	wire, err := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return cvLeafExperimentMetricsFromWireV2(leaf, wire, context)
}

func cvLeafExperimentMetricsFromWireV2(
	leaf *cvLeafV2, wire []byte, context *cvLeafContextV2,
) (ackCount, fallbackCount, proofBytes, leafWireBytes int, err error) {
	if leaf == nil || context == nil || len(wire) == 0 ||
		!bytes.Equal(leaf.Digest, hashBytes([]byte(cvLeafDigestDomainV2), wire)) {
		return 0, 0, 0, 0, fmt.Errorf("invalid verified CV V2 leaf metrics input")
	}
	for i := range leaf.Receivers {
		if leaf.Receivers[i].ACK == nil {
			continue
		}
		ackCount++
		proofWire, proofErr := cvOwnershipProofV2CanonicalBytesAfterValidation(
			&leaf.Receivers[i].ACK.Ownership, context,
		)
		if proofErr != nil {
			return 0, 0, 0, 0, proofErr
		}
		proofBytes += len(proofWire)
	}
	if leaf.Fallback != nil {
		fallbackCount = len(leaf.Fallback.ReceiverIndices)
		linkWire, linkErr := cvFallbackLinkProofV2CanonicalBytesAfterValidation(
			&leaf.Fallback.Link, context, fallbackCount,
		)
		if linkErr != nil {
			return 0, 0, 0, 0, linkErr
		}
		rangeWire, rangeErr := cvFallbackRangeProofV2CanonicalBytes(&leaf.Fallback.Range)
		if rangeErr != nil {
			return 0, 0, 0, 0, rangeErr
		}
		proofBytes += len(linkWire) + len(rangeWire)
	}
	return ackCount, fallbackCount, proofBytes, len(wire), nil
}

func poolDealerIDsV2(pool *cvPoolV2) []int {
	if pool == nil {
		return nil
	}
	dealers := make([]int, len(pool.Components))
	for i := range pool.Components {
		dealers[i] = pool.Components[i].Header.DealerID
	}
	return dealers
}
