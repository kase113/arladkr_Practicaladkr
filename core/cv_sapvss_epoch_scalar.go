package core

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// RunCVEpochScalar executes one scalar CV-sAPVSS epoch.
func RunCVEpochScalar(ctx context.Context, cfg Config) (*EpochResult, error) {
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
	runtime := c.cvRuntimeScalar
	if runtime == nil {
		var err error
		runtime, err = cvLoadEpochRuntimeScalar(c)
		if err != nil {
			return nil, err
		}
	}
	localOld := c.LocalNodeIDs[0]
	localReceiver := c.CVLocalReceiverIDs[0]
	contextDigest, err := cvLeafContextDigestScalar(runtime.context)
	if err != nil {
		return nil, err
	}
	shardBytes, err := cvEpochShardBytesUpperBoundScalar(
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
	holderStore, err := newCVAPDBHolderStoreScalar(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	decisionStore, err := newCVDecisionSignStoreScalar(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	scalarStore, err := newCVScalarStoreScalar(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	baseServiceCfg := cvAPDBNetworkServiceConfigScalar{
		SID: c.SID, Epoch: uint64(c.Epoch), OldRoster: c.OldCommittee, NewRoster: c.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(c.OldCommittee),
		DataShards: runtime.params.recoveryThreshold, ShardBytes: shardBytes, MaximumPayload: cvMaxLeafWireBytes,
		Params: runtime.params, LeafContext: runtime.context, Receivers: runtime.receivers, Validators: runtime.validators,
	}
	oldCfg := baseServiceCfg
	oldCfg.LocalNode = localOld
	oldCfg.Receivers = cvPublicReceiverMaterialScalar(runtime.receivers)
	oldCfg.DecisionStore = decisionStore
	oldService, err := newCVAPDBNetworkServiceScalar(ctx, oldCfg, transport, router, runtime.authenticator,
		holderStore, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer oldService.Close()
	receiverCfg := baseServiceCfg
	receiverCfg.LocalNode = localReceiver
	receiverCfg.Validators = cvPublicValidatorMaterialScalar(runtime.validators)
	receiverCfg.ScalarStore = scalarStore
	receiverService, err := newCVAPDBNetworkServiceScalar(ctx, receiverCfg, transport, router, runtime.authenticator,
		nil, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer receiverService.Close()

	c.runtime.setCommPhase("component_disperse")
	leafStarted := time.Now()
	leafMaterial, err := oldService.BuildLeafMaterialScalar(ctx)
	if err != nil {
		return nil, fmt.Errorf("build CV V2 quorum/fallback leaf: %w", err)
	}
	leaf := leafMaterial.leaf
	leafLatency := time.Since(leafStarted)
	ackCount, fallbackCount, proofBytes, leafWireBytes, err := cvLeafExperimentMetricsFromWireScalar(
		leaf, leafMaterial.wire, runtime.context,
	)
	if err != nil {
		return nil, err
	}
	componentStarted := time.Now()
	if _, err := oldService.PublishBuiltComponentScalar(ctx, leafMaterial); err != nil {
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
	proposers, validatorSample, err := cvDeriveEligibilitySamplesScalar(
		c.OldCommittee, eligibilityCoin.Value, runtime.params.proposerSampleSize, runtime.params.validatorSampleSize,
	)
	if err != nil || len(proposers) == 0 {
		return nil, fmt.Errorf("derive CV V2 eligibility samples: %w", err)
	}
	// The receiver actor shares this node but has a separate network service.
	// Give it the already-verified coin so post-agreement cache pulls can
	// deterministically spread requests across the same validator sample.
	if err := receiverService.setEligibilityCoin(eligibilityCoin); err != nil {
		return nil, fmt.Errorf("configure CV V2 receiver eligibility sample: %w", err)
	}
	public, err := oldService.agreementPublicContextScalar()
	if err != nil {
		return nil, fmt.Errorf("build CV V2 agreement context: %w", err)
	}
	proposerSlotsStarted := time.Now()
	candidate, err := cvRunSampledProposerSlotsScalar(
		ctx, proposers, oldService.certifiedCandidateChScalar,
		func(slotCtx context.Context, proposer int) error {
			return runCVProposerSlotScalar(
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
	decided, agreementWire, peerWait, err := cvRunAgreementScalar(ctx, c, candidate, public)
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
	aggregateWire, err := cvAggregateScalarCanonicalBytesAfterValidation(aggregate, runtime.context, runtime.params)
	if err != nil {
		return nil, err
	}
	shareWire, err := cvScalarShareOutputScalarCanonicalBytes(output)
	if err != nil {
		return nil, err
	}
	scalarBytes := scalar.Bytes()
	publicKeyBytes := publicKey.Bytes()
	serviceGraceStarted := time.Now()
	serviceGrace := cvRecoverServiceGraceScalar(c.RouteSendTimeout)
	// Keep responders alive for finalization stragglers. This grace is excluded
	// from reported protocol latency.
	if decisionGrace := cvDecisionResponderGraceScalar(); decisionGrace > serviceGrace {
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
	sampling, err := ResolveCVScalarSampling(
		len(c.OldCommittee), c.OldFaults, c.CVSamplingFailureTarget,
		runtime.params.proposerSampleSize, runtime.params.validatorSampleSize,
	)
	if err != nil {
		return nil, err
	}
	costMetrics, err := cvCalculateEpochCostMetricsScalar(
		decided, handoff, agreementWire, aggregateWire, runtime.params, validatorSample,
		oldService.CertifiedCandidateCountScalar(), len(c.OldCommittee)*shardBytes,
	)
	if err != nil {
		return nil, err
	}
	totalSent, totalRecv := c.runtime.commStats()
	phaseSent, phaseRecv := c.runtime.phaseCommStats()
	experimentMetrics := oldService.experimentMetricsScalar()
	receiverExperimentMetrics := receiverService.experimentMetricsScalar()
	cvAddCostBreakdownScalar(phaseSent, phaseRecv, experimentMetrics, receiverExperimentMetrics)
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
		AgreementMode: "single-mvba-v2", AblationMode: c.AblationMode, CVAPVSSMode: cvSAPVSSScalarProtocolVersion,
		LockedSet: append([]int(nil), poolDealerIDsScalar(pool)...), SampledSet: selectedDealers, AggRLODealers: selectedDealers,
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
		CVDealerPayloadSentBytes:                experimentMetrics.dealerPayloadSentBytes,
		CVDealerHintSentBytes:                   experimentMetrics.dealerHintSentBytes,
		CVHolderFragmentSentBytes:               experimentMetrics.holderFragmentSentBytes,
		CVComponentRecoveryLateRecvBytes:        experimentMetrics.componentRecoveryLateRecvBytes,
		CVComponentDirectPayloadHits:            experimentMetrics.componentDirectPayloadHits,
		CVComponentFragmentRecoveries:           experimentMetrics.componentFragmentRecoveries,
		CVComponentDirectGraceWait:              experimentMetrics.componentDirectGraceWait,
		CVReceiverPayloadValidationLatency:      experimentMetrics.receiverPayloadDecodeLatency,
		CVRecoveryQueueWaitLatency:              experimentMetrics.recoveryQueueWaitLatency,
		CVRecoveryWorkerLatency:                 experimentMetrics.recoveryWorkerLatency,
		CVAggregateRecoveryCacheHits:            experimentMetrics.aggregateRecoveryCacheHits,
		CVAggregateRecoveryCacheMisses:          experimentMetrics.aggregateRecoveryCacheMisses,
		CVComponentRecoveryCacheHits:            experimentMetrics.componentRecoveryCacheHits,
		CVComponentRecoveryCacheMisses:          experimentMetrics.componentRecoveryCacheMisses,
		CVAggregateRecoveryResponseLatency:      experimentMetrics.aggregateRecoveryResponseLatency,
		CVAggregateRecoveryResponseRequests:     experimentMetrics.aggregateRecoveryResponseRequests,
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

func cvRecoverServiceGraceScalar(routeSendTimeout time.Duration) time.Duration {
	grace := 2 * routeSendTimeout
	// Larger profiles keep shard responders alive across CPU scheduling skew.
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

func cvAddCostBreakdownScalar(sent, recv map[string]uint64, services ...cvServiceExperimentMetricsScalar) {
	if sent == nil || recv == nil {
		return
	}
	tagGroups := map[string][]string{
		"component_recovery_data": {cvTagAPDBRecoverGetScalar, cvTagAPDBRecoverPayloadScalar, cvTagAPDBRecoverStoreScalar},
		"arc_share":               {cvTagAggregateARCShareScalar},
		"pool_coin":               {cvTagCoinShareScalar, cvTagPoolOfferScalar, cvTagPoolCertShareScalar, cvTagPoolCertScalar},
		"validation_request":      {cvTagValidationRequestScalar, cvTagValidationSignatureScalar, cvTagValidationResultScalar},
		"candidate_relay":         {cvTagCertifiedCandidateScalar, cvTagCertifiedCandidateACKScalar, cvTagCertifiedCandidateACKProbeScalar, cvTagCertifiedCandidateAnnounceScalar, cvTagCertifiedCandidateFetchScalar, cvTagCertifiedCandidateResponseScalar},
		"decision_handoff":        {cvTagDecisionShareScalar, cvTagHandoffScalar},
		"new_share_exchange":      {cvTagAggregateShareScalar},
		// Recovery traffic excludes post-recovery key-share/PSHARE exchange.
		// These tags cover only the aggregate APDB request and holder response.
		"recovery_data": {cvTagAggregateRecoverGetScalar, cvTagAggregateRecoverCancelScalar, cvTagAggregateRecoverStoreScalar,
			cvTagAggregatePayloadGetScalar, cvTagAggregatePayloadScalar},
	}
	for _, metrics := range services {
		sent["component_apdb_dispersal"] += metrics.componentDispersalSentBytes
		recv["component_apdb_dispersal"] += metrics.componentDispersalRecvBytes
		sent["aggregate_apdb_dispersal"] += metrics.aggregateDispersalSentBytes
		recv["aggregate_apdb_dispersal"] += metrics.aggregateDispersalRecvBytes
		sent["new_aggregate_recovery"] += metrics.newAggregateRecoverySentBytes
		recv["new_aggregate_recovery"] += metrics.newAggregateRecoveryRecvBytes
		knownTags := make(map[string]struct{})
		for name, tags := range tagGroups {
			for _, tag := range tags {
				knownTags[tag] = struct{}{}
				sent[name] += metrics.tagSentBytes[tag]
				recv[name] += metrics.tagRecvBytes[tag]
			}
		}
		for _, tag := range []string{cvTagAPDBStoreScalar, cvTagAPDBStoredShareScalar, cvTagAggregateAPDBStoreScalar, cvTagAggregateARCShareScalar} {
			knownTags[tag] = struct{}{}
		}
		for tag, bytes := range metrics.tagSentBytes {
			if _, ok := knownTags[tag]; !ok {
				sent["apdb_other"] += bytes
			}
		}
		for tag, bytes := range metrics.tagRecvBytes {
			if _, ok := knownTags[tag]; !ok {
				recv["apdb_other"] += bytes
			}
		}
	}
}

type cvEpochCostMetricsScalar struct {
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

func cvCalculateEpochCostMetricsScalar(
	decided *cvAgreementObjectScalar, handoff *cvHandoffScalar, agreementWire, aggregateWire []byte,
	params cvScalarParams, validatorSample []int,
	completedCandidates, aggregateAPDBShardBytes int,
) (cvEpochCostMetricsScalar, error) {
	if decided == nil || handoff == nil || len(validatorSample) != params.validatorSampleSize || completedCandidates <= 0 ||
		aggregateAPDBShardBytes <= 0 {
		return cvEpochCostMetricsScalar{}, fmt.Errorf("invalid CV V2 epoch cost metrics input")
	}
	poolWire, err := cvPoolScalarCanonicalBytes(&decided.Pool, params)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	validationWire, err := cvValidationRequestScalarCanonicalBytes(&cvValidationRequestScalar{
		Header: decided.Header, Pool: decided.Pool, PoolCert: decided.PoolCert,
		ContributorCoin: decided.ContributorCoin, SelectedIndices: decided.SelectedIndices, ARC: decided.ARC,
	}, params)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	poolCertificate, err := cvPoolCertificateScalarCanonicalBytes(&decided.PoolCert)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	validationCertificate, err := cvValidationCertificateScalarCanonicalBytes(&decided.VCert, validatorSample)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	arc, err := cvAPDBLockScalarCanonicalBytes(&decided.ARC)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	handoffWire, err := cvHandoffScalarCanonicalBytes(handoff)
	if err != nil {
		return cvEpochCostMetricsScalar{}, err
	}
	return cvEpochCostMetricsScalar{
		completedCandidates: completedCandidates, poolBytes: len(poolWire),
		validationRequestBytes: len(validationWire), agreementObjectBytes: len(agreementWire),
		aggregatePayloadBytes: len(aggregateWire), aggregateAPDBShardBytes: aggregateAPDBShardBytes,
		poolCertificateBytes: len(poolCertificate), validationCertificateBytes: len(validationCertificate),
		arcCertificateBytes: len(arc), decisionCertificateBytes: len(handoff.DecCert), handoffBytes: len(handoffWire),
	}, nil
}

func cvLeafExperimentMetricsFromWireScalar(
	leaf *cvLeafScalar, wire []byte, context *cvLeafContextScalar,
) (ackCount, fallbackCount, proofBytes, leafWireBytes int, err error) {
	if leaf == nil || context == nil || len(wire) == 0 ||
		!bytes.Equal(leaf.Digest, hashBytes([]byte(cvLeafDigestDomainScalar), wire)) {
		return 0, 0, 0, 0, fmt.Errorf("invalid verified CV V2 leaf metrics input")
	}
	for i := range leaf.Receivers {
		if leaf.Receivers[i].ACK == nil {
			continue
		}
		ackCount++
		proofWire, proofErr := cvOwnershipProofScalarCanonicalBytesAfterValidation(
			&leaf.Receivers[i].ACK.Ownership, context,
		)
		if proofErr != nil {
			return 0, 0, 0, 0, proofErr
		}
		proofBytes += len(proofWire)
	}
	if leaf.Fallback != nil {
		fallbackCount = len(leaf.Fallback.ReceiverIndices)
		linkWire, linkErr := cvFallbackLinkProofScalarCanonicalBytesAfterValidation(
			&leaf.Fallback.Link, context, fallbackCount,
		)
		if linkErr != nil {
			return 0, 0, 0, 0, linkErr
		}
		rangeWire, rangeErr := cvFallbackRangeProofScalarCanonicalBytes(&leaf.Fallback.Range)
		if rangeErr != nil {
			return 0, 0, 0, 0, rangeErr
		}
		proofBytes += len(linkWire) + len(rangeWire)
	}
	return ackCount, fallbackCount, proofBytes, len(wire), nil
}

func poolDealerIDsScalar(pool *cvPoolScalar) []int {
	if pool == nil {
		return nil
	}
	dealers := make([]int, len(pool.Components))
	for i := range pool.Components {
		dealers[i] = pool.Components[i].Header.DealerID
	}
	return dealers
}
