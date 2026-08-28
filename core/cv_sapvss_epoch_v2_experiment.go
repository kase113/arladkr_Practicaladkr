package core

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const CVV2ReferenceExperimentProtocol = cvSAPVSSV2ProtocolVersion + "-reference"

const cvSAPVSSV2ReferenceExperimentProtocol = CVV2ReferenceExperimentProtocol

// CVV2ReferenceTimings reports wall-clock milliseconds for the academic V2
// reference experiment. Network and production persistence are intentionally
// outside this measurement.
type CVV2ReferenceTimings struct {
	KeySetup       float64 `json:"key_setup_ms"`
	LeafGeneration float64 `json:"leaf_generation_ms"`
	Components     float64 `json:"components_ms"`
	Pool           float64 `json:"pool_ms"`
	Aggregate      float64 `json:"aggregate_ms"`
	Validation     float64 `json:"validation_ms"`
	Agreement      float64 `json:"agreement_ms"`
	Handoff        float64 `json:"handoff_ms"`
	Recovery       float64 `json:"recovery_ms"`
	Shares         float64 `json:"shares_ms"`
	ReferenceEpoch float64 `json:"reference_epoch_ms"`
	Total          float64 `json:"total_ms"`
}

type CVV2ReferenceExperimentResult struct {
	Protocol           string                  `json:"protocol"`
	SID                string                  `json:"sid"`
	Epoch              uint64                  `json:"epoch"`
	OldNodes           int                     `json:"old_nodes"`
	OldFaults          int                     `json:"old_faults"`
	NewNodes           int                     `json:"new_nodes"`
	NewFaults          int                     `json:"new_faults"`
	PoolSize           int                     `json:"pool_size"`
	ComponentCount     int                     `json:"component_count"`
	NewShareThreshold  int                     `json:"new_share_threshold"`
	Sampling           CVV2SamplingReport      `json:"sampling"`
	SamplingEpochs     int                     `json:"sampling_epochs"`
	SamplingUnionBound string                  `json:"sampling_union_bound"`
	SelectedIndices    []int                   `json:"selected_indices"`
	AggregateDigest    string                  `json:"aggregate_digest"`
	HandoffDigest      string                  `json:"handoff_digest"`
	PublicKey          string                  `json:"public_key"`
	Metrics            CVV2ReferenceMetrics    `json:"metrics"`
	Timings            CVV2ReferenceTimings    `json:"timings"`
	APDBScaling        CVV2APDBScalingReport   `json:"apdb_scaling"`
	AgreementSize      CVV2AgreementSizeReport `json:"agreement_size"`
}

type CVV2ReferenceMetrics struct {
	ComponentScalarCiphertextBytes   int     `json:"component_scalar_ciphertext_bytes"`
	ComponentBlindingCiphertextBytes int     `json:"component_blinding_ciphertext_bytes"`
	ComponentOwnershipProofBytes     int     `json:"component_ownership_proof_bytes"`
	FallbackLinkProofBytes           int     `json:"fallback_link_proof_bytes"`
	FallbackRangeProofBytes          int     `json:"fallback_range_proof_bytes"`
	ComponentLeafWireBytes           int     `json:"component_leaf_wire_bytes"`
	AggregatePayloadBytes            int     `json:"aggregate_payload_bytes"`
	AggregateShareProofBytes         int     `json:"aggregate_share_proof_bytes"`
	ScalarBoundedDLogMilliseconds    float64 `json:"scalar_bounded_dlog_ms"`
	BlindingGroupDecryptMilliseconds float64 `json:"blinding_group_decryption_ms"`
}

// RunCVV2ReferenceExperiment builds and executes one all-ACK V2 epoch using
// fresh experiment-only key material below scratchRoot. It is the explicit
// reference entry point; RunEpoch uses the separate V2 network orchestration.
func RunCVV2ReferenceExperiment(cfg Config, scratchRoot string) (*CVV2ReferenceExperimentResult, error) {
	started := time.Now()
	c := NormalizeConfig(cfg)
	params, err := cvValidateV2Startup(c)
	if err != nil {
		return nil, fmt.Errorf("validate V2 reference experiment: %w", err)
	}
	if scratchRoot == "" {
		return nil, fmt.Errorf("V2 reference experiment requires a scratch directory")
	}

	keyPhase := time.Now()
	receiverPublic := filepath.Join(scratchRoot, "receiver-public")
	receiverSecret := filepath.Join(scratchRoot, "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(
		receiverPublic, receiverSecret, c.SID, uint64(c.Epoch), c.NewCommittee,
	); err != nil {
		return nil, fmt.Errorf("generate V2 receiver registry: %w", err)
	}
	receivers, err := cvLoadReceiverRegistryV2(
		receiverPublic, receiverSecret, c.SID, uint64(c.Epoch), c.NewCommittee, c.NewCommittee,
	)
	if err != nil {
		return nil, fmt.Errorf("load V2 receiver registry: %w", err)
	}

	validatorPublic := filepath.Join(scratchRoot, "validator-public")
	validatorSecret := filepath.Join(scratchRoot, "validator-secret")
	if err := cvGenerateValidatorRegistryV2(
		validatorPublic, validatorSecret, c.SID, uint64(c.Epoch), c.OldCommittee,
	); err != nil {
		return nil, fmt.Errorf("generate V2 validator registry: %w", err)
	}
	validators, err := cvLoadValidatorRegistryV2(
		validatorPublic, validatorSecret, c.SID, uint64(c.Epoch), c.OldCommittee, c.OldCommittee,
	)
	if err != nil {
		return nil, fmt.Errorf("load V2 validator registry: %w", err)
	}

	thresholdPublic := filepath.Join(scratchRoot, "threshold-public")
	thresholdSecret := filepath.Join(scratchRoot, "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(
		thresholdPublic, thresholdSecret, c.SID, uint64(c.Epoch), c.OldCommittee, params,
	); err != nil {
		return nil, fmt.Errorf("generate V2 threshold keys: %w", err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(
		thresholdPublic, thresholdSecret, c.SID, uint64(c.Epoch), c.OldCommittee, c.OldCommittee, params,
	)
	if err != nil {
		return nil, fmt.Errorf("load V2 threshold keys: %w", err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		return nil, err
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		return nil, err
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		return nil, err
	}
	keySetup := time.Since(keyPhase)

	context := &cvLeafContextV2{
		SID: c.SID, Epoch: uint64(c.Epoch), OldRoster: append([]int(nil), c.OldCommittee...),
		NewRoster:              append([]int(nil), c.NewCommittee...),
		ReceiverRegistryDigest: append([]byte(nil), receivers.registryDigest...),
		SharingDegree:          params.newShareDegree,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	leafPhase := time.Now()
	leaves := make([]*cvLeafV2, params.poolSize)
	for i := range leaves {
		leaves[i], err = cvBuildReferenceAllACKLeafV2(
			c.OldCommittee[i], context, receivers, validators,
		)
		if err != nil {
			return nil, fmt.Errorf("build V2 reference dealer %d leaf: %w", c.OldCommittee[i], err)
		}
	}
	leafGeneration := time.Since(leafPhase)

	epoch, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: context, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		return nil, err
	}
	handoffDigest, err := cvHandoffDigestV2(epoch.Handoff.ContextDigest, &epoch.Handoff.Header, &epoch.Handoff.ARC)
	if err != nil {
		return nil, err
	}
	publicKey := epoch.PublicKey.Bytes()
	metrics, err := cvReferenceMetricsV2(epoch, context)
	if err != nil {
		return nil, err
	}
	apdbScaling, err := cvMeasureAPDBScalingV2(
		apdbSigner, c.OldCommittee, []int{256, 1024, 4096, 16384, 65536},
	)
	if err != nil {
		return nil, fmt.Errorf("measure V2 APDB scaling: %w", err)
	}
	_, validatorSample, err := cvDeriveEligibilitySamplesV2(
		c.OldCommittee, epoch.EligibilityCoin.Value, params.proposerSampleSize, params.validatorSampleSize,
	)
	if err != nil {
		return nil, err
	}
	agreementSize, err := cvAgreementSizeReportV2(&epoch.Agreement, params, validatorSample)
	if err != nil {
		return nil, fmt.Errorf("measure V2 agreement size: %w", err)
	}
	sampling, err := ResolveCVV2Sampling(
		len(c.OldCommittee), c.OldFaults, c.CVSamplingFailureTarget,
		params.proposerSampleSize, params.validatorSampleSize,
	)
	if err != nil {
		return nil, err
	}
	samplingUnionBound, err := CVV2SamplingUnionBound(sampling, 1)
	if err != nil {
		return nil, err
	}
	return &CVV2ReferenceExperimentResult{
		Protocol: cvSAPVSSV2ReferenceExperimentProtocol, SID: c.SID, Epoch: uint64(c.Epoch),
		OldNodes: len(c.OldCommittee), OldFaults: params.oldFaults,
		NewNodes: len(c.NewCommittee), NewFaults: params.newFaults,
		PoolSize: params.poolSize, ComponentCount: params.componentCount,
		NewShareThreshold:  params.newShareThreshold,
		Sampling:           sampling,
		SamplingEpochs:     1,
		SamplingUnionBound: samplingUnionBound,
		SelectedIndices:    append([]int(nil), epoch.SelectedIndices...),
		AggregateDigest:    hex.EncodeToString(epoch.Aggregate.Digest),
		HandoffDigest:      hex.EncodeToString(handoffDigest),
		PublicKey:          hex.EncodeToString(publicKey[:]),
		Metrics:            metrics,
		APDBScaling:        apdbScaling,
		AgreementSize:      agreementSize,
		Timings: CVV2ReferenceTimings{
			KeySetup: millisecondsV2(keySetup), LeafGeneration: millisecondsV2(leafGeneration),
			Components: millisecondsV2(epoch.Timings.Components), Pool: millisecondsV2(epoch.Timings.Pool),
			Aggregate: millisecondsV2(epoch.Timings.Aggregate), Validation: millisecondsV2(epoch.Timings.Validation),
			Agreement: millisecondsV2(epoch.Timings.Agreement), Handoff: millisecondsV2(epoch.Timings.Handoff),
			Recovery: millisecondsV2(epoch.Timings.Recovery), Shares: millisecondsV2(epoch.Timings.Shares),
			ReferenceEpoch: millisecondsV2(epoch.Timings.Total), Total: millisecondsV2(time.Since(started)),
		},
	}, nil
}

func cvReferenceMetricsV2(
	epoch *cvReferenceEpochResultV2, context *cvLeafContextV2,
) (CVV2ReferenceMetrics, error) {
	if epoch == nil || context == nil {
		return CVV2ReferenceMetrics{}, fmt.Errorf("invalid V2 reference metrics input")
	}
	var metrics CVV2ReferenceMetrics
	const ciphertextBytes = 2 * bls12381.SizeOfG1AffineCompressed
	for i := range epoch.Components {
		component := &epoch.Components[i]
		metrics.ComponentLeafWireBytes += len(component.Payload)
		if component.Leaf == nil {
			return CVV2ReferenceMetrics{}, fmt.Errorf("nil V2 reference metric component")
		}
		for j := range component.Leaf.Receivers {
			receiver := &component.Leaf.Receivers[j]
			metrics.ComponentScalarCiphertextBytes += len(receiver.Offer.ScalarChunks) * ciphertextBytes
			metrics.ComponentBlindingCiphertextBytes += ciphertextBytes
			if receiver.ACK != nil {
				proofWire, err := cvOwnershipProofV2CanonicalBytes(&receiver.ACK.Ownership, context)
				if err != nil {
					return CVV2ReferenceMetrics{}, err
				}
				metrics.ComponentOwnershipProofBytes += len(proofWire)
			}
		}
		if component.Leaf.Fallback != nil {
			linkWire, err := cvFallbackLinkProofV2CanonicalBytes(
				&component.Leaf.Fallback.Link, context, len(component.Leaf.Fallback.ReceiverIndices),
			)
			if err != nil {
				return CVV2ReferenceMetrics{}, err
			}
			rangeWire, err := cvFallbackRangeProofV2CanonicalBytes(&component.Leaf.Fallback.Range)
			if err != nil {
				return CVV2ReferenceMetrics{}, err
			}
			metrics.FallbackLinkProofBytes += len(linkWire)
			metrics.FallbackRangeProofBytes += len(rangeWire)
		}
	}
	metrics.AggregatePayloadBytes = len(epoch.AggregatePayload)
	metrics.ScalarBoundedDLogMilliseconds = millisecondsV2(epoch.ShareDecryption.ScalarBoundedDLog)
	metrics.BlindingGroupDecryptMilliseconds = millisecondsV2(epoch.ShareDecryption.BlindingGroupDecryption)
	for _, output := range epoch.ShareOutputs {
		if output == nil || !cvValidAggregateShareProofV2(&output.Proof) {
			return CVV2ReferenceMetrics{}, fmt.Errorf("invalid V2 reference aggregate-share metric")
		}
		metrics.AggregateShareProofBytes += 4*bls12381.SizeOfG1AffineCompressed + 2*fr.Bytes
	}
	return metrics, nil
}

func cvBuildReferenceAllACKLeafV2(
	dealer int, context *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	if context == nil || receivers == nil || validators == nil {
		return nil, fmt.Errorf("invalid V2 reference leaf input")
	}
	count := context.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, count)
	blindingCoefficients := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	commitments, coreProof, err := cvProveCoreV2(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		return nil, err
	}
	offers := make([]*cvReceiverLaneOfferV2, len(context.NewRoster))
	acks := make([]*cvACKEvidenceV2, len(context.NewRoster))
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		offers[i], _, err = cvEncryptReceiverLanesV2(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			return nil, err
		}
		encryptionSecret, ok := receivers.localEncryptionSecrets[receiverID]
		if !ok {
			return nil, fmt.Errorf("V2 reference receiver %d lacks encryption secret", receiverID)
		}
		identitySecret, ok := receivers.localIdentitySecrets[receiverID]
		if !ok {
			return nil, fmt.Errorf("V2 reference receiver %d lacks identity secret", receiverID)
		}
		acks[i], _, _, err = cvVerifyDecryptAndSignACKV2(
			context, dealer, offers[i], &receivers.encryptionPublicKeys[i], encryptionSecret,
			receivers.identityPublicKeys[i], identitySecret,
		)
		if err != nil {
			return nil, err
		}
	}
	return cvBuildAllACKLeafV2(context, dealer, commitments, coreProof, offers, acks, receivers, validators)
}

func cvEvaluateScalarPolynomialV2(coefficients []fr.Element, receiverIndex int) fr.Element {
	var x fr.Element
	x.SetInt64(int64(receiverIndex))
	powers := cvFrPowers(x, len(coefficients))
	var result fr.Element
	for i := range coefficients {
		var term fr.Element
		term.Mul(&coefficients[i], &powers[i])
		result.Add(&result, &term)
	}
	return result
}

func millisecondsV2(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
