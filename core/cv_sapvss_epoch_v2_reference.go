package core

import (
	"bytes"
	"fmt"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const cvComponentPayloadDigestV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/component-payload"

// cvReferenceEpochInputV2 contains the cryptographic material used by the
// deterministic, in-memory V2 experiment. Leaves are supplied by the dealers;
// this runner starts at their public verification and APDB dispersal.
type cvReferenceEpochInputV2 struct {
	Context       *cvLeafContextV2
	Params        cvV2Params
	Leaves        []*cvLeafV2
	Receivers     *cvReceiverKeyMaterialV2
	Validators    *cvValidatorKeyMaterialV2
	APDBSigner    *tblsThresholdSigner
	ControlSigner *tblsThresholdSigner
	CoinSigner    *tblsThresholdSigner
}

type cvReferenceEpochTimingsV2 struct {
	Components time.Duration
	Pool       time.Duration
	Aggregate  time.Duration
	Validation time.Duration
	Agreement  time.Duration
	Handoff    time.Duration
	Recovery   time.Duration
	Shares     time.Duration
	Total      time.Duration
}

type cvReferenceComponentV2 struct {
	Leaf    *cvLeafV2
	Payload []byte
	Header  cvComponentHeaderV2
	Lock    cvAPDBLockV2
	encoded *cvAPDBEncodedV2
}

type cvReferenceEpochResultV2 struct {
	Components         []cvReferenceComponentV2
	Pool               cvPoolV2
	PoolCert           cvPoolCertificateV2
	EligibilityCoin    cvCoinOutputV2
	ContributorCoin    cvCoinOutputV2
	SelectedIndices    []int
	Aggregate          *cvAggregateV2
	AggregatePayload   []byte
	Header             cvAggregateHeaderV2
	VCert              cvValidationCertificateV2
	ARC                cvAPDBLockV2
	Agreement          cvAgreementObjectV2
	AgreementWire      []byte
	Handoff            cvHandoffV2
	HandoffWire        []byte
	RecoveredAggregate *cvAggregateV2
	ShareOutputs       []*cvScalarShareOutputV2
	localScalarShares  map[int][]byte
	ShareDecryption    cvAggregateShareDecryptionTimingsV2
	PublicKey          bls12381.G1Affine
	Timings            cvReferenceEpochTimingsV2
}

// cvRunReferenceEpochV2 composes the V2 cryptographic objects without network,
// persistence, or a production MVBA implementation. The agreement step still
// serializes the candidate and invokes the exact public MVBA predicate.
func cvRunReferenceEpochV2(input cvReferenceEpochInputV2) (*cvReferenceEpochResultV2, error) {
	started := time.Now()
	if err := cvValidateReferenceEpochInputV2(input); err != nil {
		return nil, err
	}
	result := &cvReferenceEpochResultV2{}
	contextDigest, err := cvLeafContextDigestV2(input.Context)
	if err != nil {
		return nil, fmt.Errorf("reference V2 context digest: %w", err)
	}
	oldRoster := input.Context.OldRoster
	dataShards := input.Params.recoveryThreshold

	phase := time.Now()
	result.Components = make([]cvReferenceComponentV2, len(input.Leaves))
	refs := make([]cvComponentRefV2, len(input.Leaves))
	for i, leaf := range input.Leaves {
		if err := cvVerifyAPVSSV2(leaf, input.Context, input.Receivers, input.Validators); err != nil {
			return nil, fmt.Errorf("reference V2 component %d verification: %w", i, err)
		}
		payload, err := cvLeafV2CanonicalBytes(leaf, input.Receivers, input.Validators)
		if err != nil {
			return nil, fmt.Errorf("reference V2 component %d codec: %w", i, err)
		}
		instance, err := cvComponentInstanceDigestV2(contextDigest, leaf.DealerID)
		if err != nil {
			return nil, err
		}
		encoded, err := cvAPDBEncodeV2(instance, payload, dataShards, len(oldRoster), cvMaxLeafWireBytes)
		if err != nil {
			return nil, fmt.Errorf("reference V2 component %d APDB encode: %w", i, err)
		}
		lock, err := cvReferenceAPDBLockV2(encoded, oldRoster, input.APDBSigner)
		if err != nil {
			return nil, fmt.Errorf("reference V2 component %d APDB lock: %w", i, err)
		}
		header := cvComponentHeaderV2{
			ContextDigest: append([]byte(nil), contextDigest...), DealerID: leaf.DealerID,
			PayloadDigest: cvComponentPayloadDigestV2(payload), Instance: append([]byte(nil), instance...),
			Root: append([]byte(nil), encoded.root...),
		}
		refs[i] = cvComponentRefV2{Header: header, Lock: *lock}
		result.Components[i] = cvReferenceComponentV2{Leaf: leaf, Payload: payload, Header: header, Lock: *lock, encoded: encoded}
	}
	result.Timings.Components = time.Since(phase)

	phase = time.Now()
	eligibilityCoin, err := cvReferenceCoinV2(
		input.CoinSigner, oldRoster, func() ([]byte, error) {
			return cvEligibilityCoinInvocationV2(input.Context.SID, input.Context.Epoch)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 eligibility coin: %w", err)
	}
	proposers, validatorSample, err := cvDeriveEligibilitySamplesV2(
		oldRoster, eligibilityCoin.Value, input.Params.proposerSampleSize, input.Params.validatorSampleSize,
	)
	if err != nil {
		return nil, err
	}
	proposer := proposers[0]
	pool, err := cvBuildPoolV2(contextDigest, proposer, refs, input.Params)
	if err != nil {
		return nil, fmt.Errorf("reference V2 pool: %w", err)
	}
	poolStatement, err := cvPoolCertificateStatementV2(contextDigest, proposer, pool.Digest)
	if err != nil {
		return nil, err
	}
	poolCertificate, err := cvReferenceThresholdCertificateV2(
		input.ControlSigner, oldRoster, cvPoolCertV2Domain, poolStatement,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 PoolCert: %w", err)
	}
	poolCert := cvPoolCertificateV2{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: poolCertificate}
	if err := cvVerifyPoolCertificateV2(pool, &poolCert, input.ControlSigner); err != nil {
		return nil, err
	}
	contributorCoin, err := cvReferenceCoinV2(
		input.CoinSigner, oldRoster, func() ([]byte, error) {
			return cvContributorCoinInvocationV2(contextDigest, proposer, pool.Digest)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 contributor coin: %w", err)
	}
	selected, err := cvSelectedPoolIndicesV2(input.Params.poolSize, input.Params.componentCount, contributorCoin.Value)
	if err != nil {
		return nil, err
	}
	result.EligibilityCoin = *eligibilityCoin
	result.ContributorCoin = *contributorCoin
	result.Pool = *pool
	result.PoolCert = poolCert
	result.SelectedIndices = append([]int(nil), selected...)
	result.Timings.Pool = time.Since(phase)

	phase = time.Now()
	selectedLeaves := make([]*cvLeafV2, len(selected))
	for i, poolIndex := range selected {
		component := &result.Components[poolIndex]
		payload, err := cvRecoverAPDBV2(
			&component.Lock, component.encoded.stores[:dataShards], dataShards, len(oldRoster),
			component.encoded.shardBytes, cvMaxLeafWireBytes,
			func(recovered []byte) error {
				if !bytes.Equal(cvComponentPayloadDigestV2(recovered), component.Header.PayloadDigest) {
					return fmt.Errorf("component payload digest mismatch")
				}
				return nil
			},
		)
		if err != nil {
			return nil, fmt.Errorf("reference V2 selected component %d recovery: %w", poolIndex, err)
		}
		selectedLeaves[i], err = cvDecodeLeafV2(payload, input.Context, input.Receivers, input.Validators)
		if err != nil {
			return nil, fmt.Errorf("reference V2 selected component %d decode: %w", poolIndex, err)
		}
	}
	aggregate, err := cvAggV2(selectedLeaves, input.Context, input.Params, input.Receivers, input.Validators)
	if err != nil {
		return nil, fmt.Errorf("reference V2 aggregate: %w", err)
	}
	aggregatePayload, err := cvAggregateV2CanonicalBytesAfterValidation(aggregate, input.Context, input.Params)
	if err != nil {
		return nil, err
	}
	selectionDigest, err := cvSelectionDigestV2(contributorCoin, selected, input.Params.poolSize, input.Params.componentCount)
	if err != nil {
		return nil, err
	}
	aggregateInstance, err := cvAggregateInstanceDigestV2(contextDigest, proposer, pool.Digest, selectionDigest)
	if err != nil {
		return nil, err
	}
	aggregateEncoded, err := cvAPDBEncodeV2(
		aggregateInstance, aggregatePayload, dataShards, len(oldRoster), cvMaxLeafWireBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 aggregate APDB encode: %w", err)
	}
	arc, err := cvReferenceAPDBLockV2(aggregateEncoded, oldRoster, input.APDBSigner)
	if err != nil {
		return nil, fmt.Errorf("reference V2 ARC: %w", err)
	}
	payloadDigest, err := cvAggregatePayloadDigestV2(aggregatePayload)
	if err != nil {
		return nil, err
	}
	header := cvAggregateHeaderV2{
		ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
		SelectionDigest: selectionDigest, AggregateDigest: append([]byte(nil), aggregate.Digest...),
		PayloadDigest: payloadDigest, APDBInstance: aggregateInstance, APDBRoot: append([]byte(nil), aggregateEncoded.root...),
	}
	if err := cvVerifyAggregateHeaderPayloadV2(&header, aggregatePayload, aggregate); err != nil {
		return nil, err
	}
	result.Aggregate = aggregate
	result.AggregatePayload = append([]byte(nil), aggregatePayload...)
	result.Header = header
	result.ARC = *arc
	result.Timings.Aggregate = time.Since(phase)

	phase = time.Now()
	verifiedAggregate, err := cvAVerV2(
		aggregatePayload, selectedLeaves, input.Context, input.Params, input.Receivers, input.Validators,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 sampled validation: %w", err)
	}
	if !bytes.Equal(verifiedAggregate.Digest, aggregate.Digest) {
		return nil, fmt.Errorf("reference V2 sampled validators disagreed on aggregate")
	}
	votes := make(map[int][]byte, input.Params.validatorThreshold)
	for _, member := range validatorSample[:input.Params.validatorThreshold] {
		votes[member], err = cvSignValidationV2(member, &header, validatorSample, input.Validators)
		if err != nil {
			return nil, fmt.Errorf("reference V2 validator %d vote: %w", member, err)
		}
	}
	vCert, err := cvBuildValidationCertificateV2(
		&header, validatorSample, input.Params.validatorThreshold, votes, input.Validators,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 VCert: %w", err)
	}
	result.VCert = *vCert
	result.Timings.Validation = time.Since(phase)

	phase = time.Now()
	agreement := cvAgreementObjectV2{
		Header: header, Pool: *pool, PoolCert: poolCert, ContributorCoin: *contributorCoin,
		SelectedIndices: append([]int(nil), selected...), VCert: *vCert, ARC: *arc,
	}
	public := cvAgreementPublicContextV2{
		SID: input.Context.SID, Epoch: input.Context.Epoch, ContextDigest: contextDigest,
		OldCommittee: append([]int(nil), oldRoster...), EligibilityCoin: eligibilityCoin, Params: input.Params,
		APDBSigner: input.APDBSigner, ControlSigner: input.ControlSigner, CoinSigner: input.CoinSigner,
		ValidatorKeys: input.Validators,
	}
	agreementWire, err := cvAgreementObjectV2CanonicalBytes(&agreement, input.Params, validatorSample)
	if err != nil {
		return nil, err
	}
	if !cvAggregatePredicateV2(public)(proposer, agreementWire) {
		return nil, fmt.Errorf("reference V2 MVBA public predicate rejected candidate")
	}
	result.Agreement = agreement
	result.AgreementWire = append([]byte(nil), agreementWire...)
	result.Timings.Agreement = time.Since(phase)

	phase = time.Now()
	decisionStatement, err := cvDecisionStatementV2(contextDigest, &header, arc)
	if err != nil {
		return nil, err
	}
	decCert, err := cvReferenceThresholdCertificateV2(
		input.ControlSigner, oldRoster, cvDecisionCertificateV2Domain, decisionStatement,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 DecCert: %w", err)
	}
	handoff := cvHandoffV2{ContextDigest: contextDigest, Header: header, ARC: *arc, DecCert: decCert}
	handoffWire, err := cvHandoffV2CanonicalBytes(&handoff)
	if err != nil {
		return nil, err
	}
	decodedHandoff, err := cvDecodeHandoffV2(handoffWire)
	if err != nil {
		return nil, fmt.Errorf("reference V2 handoff verification: %w", err)
	}
	if err := cvVerifyHandoffV2(decodedHandoff, contextDigest, input.APDBSigner, input.ControlSigner); err != nil {
		return nil, fmt.Errorf("reference V2 handoff verification: %w", err)
	}
	result.Handoff = *decodedHandoff
	result.HandoffWire = append([]byte(nil), handoffWire...)
	result.Timings.Handoff = time.Since(phase)

	phase = time.Now()
	requestWire, err := cvAggregateRecoveryRequestV2CanonicalBytes(
		&cvAggregateRecoveryRequestV2{Handoff: *decodedHandoff},
	)
	if err != nil {
		return nil, err
	}
	collector, err := newCVAggregateRecoveryCollectorV2(
		requestWire, contextDigest, oldRoster, dataShards, aggregateEncoded.shardBytes, cvMaxLeafWireBytes,
		input.APDBSigner, input.ControlSigner,
		func(recovered []byte) error {
			candidate, decodeErr := cvDecodeAggregateV2(recovered, input.Context, input.Params)
			if decodeErr != nil {
				return decodeErr
			}
			return cvVerifyAggregateHeaderPayloadV2(&header, recovered, candidate)
		},
	)
	if err != nil {
		return nil, err
	}
	for i := 0; i < dataShards; i++ {
		storeWire, encodeErr := cvAPDBStoreV2CanonicalBytes(
			&aggregateEncoded.stores[i], len(oldRoster), aggregateEncoded.shardBytes,
		)
		if encodeErr != nil {
			return nil, encodeErr
		}
		if _, addErr := collector.AddStore(oldRoster[i], storeWire); addErr != nil {
			return nil, addErr
		}
	}
	recoveredPayload, err := collector.Recover()
	if err != nil {
		return nil, fmt.Errorf("reference V2 aggregate recovery: %w", err)
	}
	recoveredAggregate, err := cvDecodeAggregateV2(recoveredPayload, input.Context, input.Params)
	if err != nil {
		return nil, fmt.Errorf("reference V2 recovered aggregate mismatch: %w", err)
	}
	if !bytes.Equal(recoveredAggregate.Digest, aggregate.Digest) {
		return nil, fmt.Errorf("reference V2 recovered aggregate digest mismatch")
	}
	result.RecoveredAggregate = recoveredAggregate
	result.Timings.Recovery = time.Since(phase)

	phase = time.Now()
	result.ShareOutputs = make([]*cvScalarShareOutputV2, len(input.Context.NewRoster))
	result.localScalarShares = make(map[int][]byte, len(input.Context.NewRoster))
	for i, receiverID := range input.Context.NewRoster {
		secret, ok := input.Receivers.localEncryptionSecrets[receiverID]
		if !ok {
			return nil, fmt.Errorf("reference V2 receiver %d lacks decryption secret", receiverID)
		}
		scalar, output, decryptTimings, err := cvDecryptAggregateShareMeasuredV2(
			recoveredAggregate, input.Context, input.Params, receiverID, i+1,
			&input.Receivers.encryptionPublicKeys[i], secret,
		)
		if err != nil {
			return nil, fmt.Errorf("reference V2 receiver %d aggregate share: %w", receiverID, err)
		}
		result.ShareDecryption.ScalarBoundedDLog += decryptTimings.ScalarBoundedDLog
		result.ShareDecryption.BlindingGroupDecryption += decryptTimings.BlindingGroupDecryption
		encodedScalar := scalar.Bytes()
		result.localScalarShares[receiverID] = append([]byte(nil), encodedScalar[:]...)
		wire, err := cvScalarShareOutputV2CanonicalBytes(output)
		if err != nil {
			return nil, err
		}
		result.ShareOutputs[i], err = cvDecodeScalarShareOutputV2(
			wire, recoveredAggregate, input.Context, input.Params, input.Receivers,
		)
		if err != nil {
			return nil, fmt.Errorf("reference V2 receiver %d share verification: %w", receiverID, err)
		}
	}
	publicKey, err := cvRecoverThresholdPublicKeyV2(
		result.ShareOutputs[:input.Params.newShareThreshold], recoveredAggregate,
		input.Context, input.Params, input.Receivers,
	)
	if err != nil {
		return nil, fmt.Errorf("reference V2 public-key interpolation: %w", err)
	}
	result.PublicKey = publicKey
	result.Timings.Shares = time.Since(phase)
	result.Timings.Total = time.Since(started)
	return result, nil
}

func cvValidateReferenceEpochInputV2(input cvReferenceEpochInputV2) error {
	if input.Context == nil || len(input.Leaves) != input.Params.poolSize || input.Params.poolSize <= 0 ||
		input.Params.componentCount <= 0 || input.Params.componentCount > input.Params.poolSize ||
		input.Params.recoveryThreshold <= 0 || input.Params.recoveryThreshold > len(input.Context.OldRoster) ||
		input.Params.newShareThreshold <= 0 || input.Params.newShareThreshold > len(input.Context.NewRoster) ||
		input.Params.proposerSampleSize <= 0 || input.Params.proposerSampleSize > len(input.Context.OldRoster) ||
		input.Params.validatorSampleSize <= 0 || input.Params.validatorSampleSize > len(input.Context.OldRoster) ||
		input.Params.validatorThreshold <= 0 || input.Params.validatorThreshold > input.Params.validatorSampleSize ||
		cvValidateLeafContextV2(input.Context) != nil ||
		cvValidateReceiverMaterialForLeafV2(input.Context, input.Receivers) != nil ||
		cvValidateValidatorMaterialForLeafV2(input.Context, input.Validators) != nil ||
		!cvV2SignerHasRole(input.APDBSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(input.ControlSigner, cvV2RoleControl) ||
		!cvV2SignerHasRole(input.CoinSigner, cvV2RoleCoin) {
		return fmt.Errorf("invalid reference V2 epoch input")
	}
	if !equalInts(input.Context.OldRoster, input.APDBSigner.memberOrder) ||
		!equalInts(input.Context.OldRoster, input.ControlSigner.memberOrder) ||
		!equalInts(input.Context.OldRoster, input.CoinSigner.memberOrder) ||
		input.APDBSigner.Threshold() != input.Params.apdbLockThreshold ||
		input.ControlSigner.Threshold() != input.Params.decisionThreshold ||
		input.CoinSigner.Threshold() != input.Params.componentCount ||
		input.Context.SharingDegree != input.Params.newShareDegree ||
		input.Context.Profile.chunkBits != 8 ||
		input.Context.Profile.maxComponents != input.Params.componentCount {
		return fmt.Errorf("reference V2 epoch parameters do not match context or keys")
	}
	lastDealer := -1
	for _, leaf := range input.Leaves {
		if leaf == nil || leaf.DealerID <= lastDealer {
			return fmt.Errorf("reference V2 leaves must have distinct increasing dealers")
		}
		lastDealer = leaf.DealerID
	}
	return nil
}

func cvComponentPayloadDigestV2(payload []byte) []byte {
	return hashBytes([]byte(cvComponentPayloadDigestV2Domain), payload)
}

func cvReferenceAPDBLockV2(
	encoded *cvAPDBEncodedV2, members []int, signer *tblsThresholdSigner,
) (*cvAPDBLockV2, error) {
	if encoded == nil {
		return nil, fmt.Errorf("nil reference V2 APDB encoding")
	}
	statement, err := cvAPDBStoredStatementV2(encoded.instanceDigest, encoded.root)
	if err != nil {
		return nil, err
	}
	certificate, err := cvReferenceThresholdCertificateV2(signer, members, cvAPDBStoredDomain, statement)
	if err != nil {
		return nil, err
	}
	lock, err := cvNewAPDBLockV2(encoded, certificate)
	if err != nil {
		return nil, err
	}
	if err := cvVerifyAPDBLockV2(lock, signer); err != nil {
		return nil, err
	}
	return lock, nil
}

func cvReferenceCoinV2(
	signer *tblsThresholdSigner, members []int, invocation func() ([]byte, error),
) (*cvCoinOutputV2, error) {
	wire, err := invocation()
	if err != nil {
		return nil, err
	}
	digest, err := cvCoinInvocationDigestV2(wire)
	if err != nil {
		return nil, err
	}
	certificate, err := cvReferenceThresholdCertificateV2(signer, members, cvV2CoinDomain, digest)
	if err != nil {
		return nil, err
	}
	return cvBuildCoinOutputV2(wire, certificate, signer)
}

func cvReferenceThresholdCertificateV2(
	signer *tblsThresholdSigner, members []int, domain string, statement []byte,
) ([]byte, error) {
	if signer == nil || len(members) < signer.Threshold() || !equalInts(members, signer.memberOrder) {
		return nil, fmt.Errorf("invalid reference V2 threshold signer")
	}
	shares := make(map[int][]byte, signer.Threshold())
	for _, member := range members {
		if len(shares) == signer.Threshold() {
			break
		}
		if !cvThresholdSignerCanSignV2(signer, member) {
			continue
		}
		share, err := signer.SignShare(member, domain, statement)
		if err != nil {
			return nil, err
		}
		shares[member] = share
	}
	if len(shares) != signer.Threshold() {
		return nil, fmt.Errorf("insufficient local shares for reference V2 certificate")
	}
	return signer.Recover(domain, statement, shares)
}
