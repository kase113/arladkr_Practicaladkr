package core

import (
	"bytes"
	"compress/flate"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvAllACKLeafScalarFixture(
	t *testing.T,
) (*cvLeafScalar, *cvLeafContextScalar, *cvReceiverKeyMaterialScalar, *cvValidatorKeyMaterialScalar) {
	t.Helper()
	cfg := cvScalarParamsTestConfig()
	receiverPublicDir := filepath.Join(t.TempDir(), "receiver-public")
	receiverSecretDir := filepath.Join(t.TempDir(), "receiver-secret")
	if err := cvGenerateReceiverRegistryScalar(
		receiverPublicDir, receiverSecretDir, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee,
	); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryScalar(
		receiverPublicDir, receiverSecretDir, cfg.SID, uint64(cfg.Epoch),
		cfg.NewCommittee, cfg.NewCommittee,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatorPublicDir := filepath.Join(t.TempDir(), "validator-public")
	validatorSecretDir := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryScalar(
		validatorPublicDir, validatorSecretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee,
	); err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryScalar(
		validatorPublicDir, validatorSecretDir, cfg.SID, uint64(cfg.Epoch),
		cfg.OldCommittee, cfg.OldCommittee,
	)
	if err != nil {
		t.Fatal(err)
	}
	context := &cvLeafContextScalar{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch),
		OldRoster: append([]int(nil), cfg.OldCommittee...), NewRoster: append([]int(nil), cfg.NewCommittee...),
		ReceiverRegistryDigest: append([]byte(nil), receivers.registryDigest...),
		SharingDegree:          len(cfg.NewCommittee) - cfg.NewFaults - 1,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: cfg.OldFaults + 1},
	}
	coefficientCount := context.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, coefficientCount)
	blindingCoefficients := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
	}
	dealer := cfg.OldCommittee[0]
	commitments, coreProof, err := cvProveCoreScalar(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		t.Fatal(err)
	}
	offers := make([]*cvReceiverLaneOfferScalar, len(cfg.NewCommittee))
	acks := make([]*cvACKEvidenceScalar, len(cfg.NewCommittee))
	for i, receiverID := range cfg.NewCommittee {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialScalar(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialScalar(blindingCoefficients, index)
		offers[i], _, err = cvEncryptReceiverLanesScalar(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			t.Fatal(err)
		}
		acks[i], _, _, err = cvVerifyDecryptAndSignACKScalar(
			context, dealer, offers[i], &receivers.encryptionPublicKeys[i],
			receivers.localEncryptionSecrets[receiverID], receivers.identityPublicKeys[i],
			receivers.localIdentitySecrets[receiverID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	leaf, err := cvBuildAllACKLeafScalar(
		context, dealer, commitments, coreProof, offers, acks, receivers, validators,
	)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, context, receivers, validators
}

func TestCVAllACKLeafScalarBuildVerifyAndCodec(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	if err := cvVerifyAPVSSScalar(leaf, context, receivers, validators); err != nil {
		t.Fatalf("verify all-ACK V2 leaf: %v", err)
	}
	wire, err := cvLeafScalarCanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	wantWireBytes, err := cvLeafWireSizeScalar(context, chunks, 0)
	if err != nil || len(wire) != wantWireBytes {
		t.Fatalf("all-ACK V2 leaf sizing mismatch: got=%d want=%d err=%v", len(wire), wantWireBytes, err)
	}
	decoded, err := cvDecodeLeafScalar(wire, context, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, leaf.Digest) ||
		cvVerifyAPVSSScalar(decoded, context, receivers, validators) != nil {
		t.Fatal("decoded all-ACK V2 leaf did not verify")
	}
	if _, err := cvDecodeLeafScalar(append(append([]byte(nil), wire...), 0),
		context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with trailing bytes")
	}
}

func TestCVReceiverEvaluationBatchScalarMatchesExactVerification(t *testing.T) {
	leaf, context, _, _ := cvAllACKLeafScalarFixture(t)
	evaluations := make([]bls12381.G1Affine, len(leaf.Receivers))
	for index := range leaf.Receivers {
		evaluations[index] = leaf.Receivers[index].Offer.Evaluation
	}
	if err := cvVerifyReceiverEvaluationsExactScalar(leaf.CoefficientCommitments, evaluations); err != nil {
		t.Fatalf("exact receiver evaluation verification: %v", err)
	}
	for _, validatePoints := range []bool{true, false} {
		if err := cvVerifyReceiverEvaluationsBatchScalar(
			context, leaf.DealerID, leaf.CoefficientCommitments, evaluations, validatePoints,
		); err != nil {
			t.Fatalf("batch receiver evaluation verification validate_points=%t: %v", validatePoints, err)
		}
	}

	mutated := append([]bls12381.G1Affine(nil), evaluations...)
	mutated[len(mutated)-1].Add(&mutated[len(mutated)-1], &genG1)
	if err := cvVerifyReceiverEvaluationsBatchScalar(
		context, leaf.DealerID, leaf.CoefficientCommitments, mutated, false,
	); err == nil {
		t.Fatal("batch receiver evaluation verification accepted a mutated evaluation")
	}
}

func TestCVOwnershipBatchScalarMatchesExactAndRejectsMutations(t *testing.T) {
	leaf, context, receivers, _ := cvAllACKLeafScalarFixture(t)
	offers := make([]*cvReceiverLaneOfferScalar, len(leaf.Receivers))
	keys := append([]bls12381.G1Affine(nil), receivers.encryptionPublicKeys...)
	for i := range leaf.Receivers {
		offers[i] = &leaf.Receivers[i].Offer
		if err := cvVerifyOwnershipScalar(context, leaf.DealerID, offers[i], &keys[i]); err != nil {
			t.Fatalf("exact ownership verification receiver %d: %v", i+1, err)
		}
	}
	for _, validatePoints := range []bool{true, false} {
		if err := cvVerifyOwnershipBatchScalar(
			context, leaf.DealerID, offers, keys, validatePoints,
		); err != nil {
			t.Fatalf("batch ownership verification validate_points=%t: %v", validatePoints, err)
		}
	}

	mutations := []struct {
		name   string
		mutate func(*cvReceiverLaneOfferScalar)
	}{
		{
			name: "commitment",
			mutate: func(offer *cvReceiverLaneOfferScalar) {
				offer.Ownership.ScalarCoinCommitments[0].Add(
					&offer.Ownership.ScalarCoinCommitments[0], &genG1,
				)
			},
		},
		{
			name: "response",
			mutate: func(offer *cvReceiverLaneOfferScalar) {
				var one fr.Element
				one.SetOne()
				offer.Ownership.BlindingShareResponse.Add(
					&offer.Ownership.BlindingShareResponse, &one,
				)
			},
		},
		{
			name: "ciphertext",
			mutate: func(offer *cvReceiverLaneOfferScalar) {
				offer.ScalarChunks[0].c.Add(&offer.ScalarChunks[0].c, &genG1)
			},
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutatedOffers := append([]*cvReceiverLaneOfferScalar(nil), offers...)
			mutatedOffers[len(mutatedOffers)-1] = cvCloneReceiverLaneOfferScalar(
				offers[len(offers)-1],
			)
			mutation.mutate(mutatedOffers[len(mutatedOffers)-1])
			if err := cvVerifyOwnershipBatchScalar(
				context, leaf.DealerID, mutatedOffers, keys, false,
			); err == nil {
				t.Fatal("batch ownership verification accepted a mutation")
			}
		})
	}
}

func TestCVAllACKLeafScalarRejectsCryptographicMutations(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)

	badEvaluation := *leaf
	badEvaluation.Receivers = append([]cvLeafReceiverScalar(nil), leaf.Receivers...)
	badEvaluation.Receivers[0] = leaf.Receivers[0]
	badEvaluation.Receivers[0].Offer = *cvCloneReceiverLaneOfferScalar(&leaf.Receivers[0].Offer)
	badEvaluation.Receivers[0].Offer.Evaluation.Add(
		&badEvaluation.Receivers[0].Offer.Evaluation, &genG1,
	)
	if err := cvVerifyAPVSSScalar(&badEvaluation, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with wrong polynomial evaluation")
	}

	badACK := *leaf
	badACK.Receivers = append([]cvLeafReceiverScalar(nil), leaf.Receivers...)
	badACK.Receivers[0] = leaf.Receivers[0]
	badACK.Receivers[0].ACK = &cvACKEvidenceScalar{
		Ownership: cvCloneOwnershipProofScalar(&leaf.Receivers[0].ACK.Ownership),
		Signature: append([]byte(nil), leaf.Receivers[0].ACK.Signature...),
	}
	badACK.Receivers[0].ACK.Signature[0] ^= 1
	if err := cvVerifyAPVSSScalar(&badACK, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated ACK")
	}

	badDealer := *leaf
	badDealer.DealerSignature = append([]byte(nil), leaf.DealerSignature...)
	badDealer.DealerSignature[0] ^= 1
	if err := cvVerifyAPVSSScalar(&badDealer, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated dealer signature")
	}

	badDigest := *leaf
	badDigest.Digest = append([]byte(nil), leaf.Digest...)
	badDigest.Digest[0] ^= 1
	if err := cvVerifyAPVSSScalar(&badDigest, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated digest")
	}
}

func TestCVLeafScalarDecodedPathRejectsResignedOwnershipMutation(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	mutated := *leaf
	mutated.Receivers = append([]cvLeafReceiverScalar(nil), leaf.Receivers...)
	mutated.Receivers[0] = leaf.Receivers[0]
	mutated.Receivers[0].Offer = *cvCloneReceiverLaneOfferScalar(&leaf.Receivers[0].Offer)
	mutated.Receivers[0].Offer.Ownership.ScalarCipherCommitments[0].Add(
		&mutated.Receivers[0].Offer.Ownership.ScalarCipherCommitments[0], &genG1,
	)
	mutated.Receivers[0].ACK = &cvACKEvidenceScalar{
		Ownership: cvCloneOwnershipProofScalar(&mutated.Receivers[0].Offer.Ownership),
		Signature: append([]byte(nil), leaf.Receivers[0].ACK.Signature...),
	}
	unsigned, err := cvLeafScalarUnsignedCanonicalBytesAfterValidation(&mutated, receivers)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := validators.localSecrets[mutated.DealerID]
	if !ok {
		t.Fatal("missing dealer signing secret")
	}
	mutated.DealerSignature, err = cvSignValidatorScalar(
		secret, cvDealerSignatureDomainScalar, hashBytes([]byte(cvDealerSignatureDomainScalar), unsigned),
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafScalarCanonicalBytesAfterValidation(&mutated, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeLeafScalar(wire, context, receivers, validators); err == nil {
		t.Fatal("decoded V2 path accepted a resigned ownership-proof mutation")
	}
}

func TestCVLeafScalarMixedACKFallbackBuildVerifyAndCodec(t *testing.T) {
	_, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	fallbackIndex := 1
	mixed := cvBuildMixedLeafScalarForTest(t, context, receivers, validators, fallbackIndex)
	if err := cvVerifyAPVSSScalar(mixed, context, receivers, validators); err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafScalarCanonicalBytes(mixed, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	wantWireBytes, err := cvLeafWireSizeScalar(context, chunks, 1)
	if err != nil || len(wire) != wantWireBytes {
		t.Fatalf("mixed V2 leaf sizing mismatch: got=%d want=%d err=%v", len(wire), wantWireBytes, err)
	}
	decoded, err := cvDecodeLeafScalar(wire, context, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Receivers[fallbackIndex-1].ACK != nil ||
		len(decoded.Receivers[fallbackIndex-1].Offer.Ownership.ScalarCoinResponses) != 0 {
		t.Fatal("fallback receiver wire retained redundant ownership/ACK evidence")
	}
	bad := *mixed
	badFallback := *mixed.Fallback
	badRange := badFallback.Range
	badRange.proof = apvssCloneCompactRangeProofForTest(badFallback.Range.proof)
	one := fr.One()
	badRange.proof.tHat.Add(&badRange.proof.tHat, &one)
	badFallback.Range = badRange
	bad.Fallback = &badFallback
	if err := cvVerifyAPVSSScalar(&bad, context, receivers, validators); err == nil {
		t.Fatal("accepted mixed CV V2 leaf with mutated fallback range proof")
	}
}

func TestCVLeafScalarTransportCompressionUsesRealCanonicalLeaf(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	payload, err := cvLeafScalarCanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	instance := hashBytes([]byte("real canonical leaf transport compression"))
	legacy, err := cvAPDBPayloadResponseScalarCanonicalBytes(&cvAPDBPayloadResponseScalar{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := cvAPDBPayloadResponseScalarTransportBytes(&cvAPDBPayloadResponseScalar{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAPDBPayloadResponseScalar(transport, len(payload))
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("real leaf transport compression round trip: err=%v", err)
	}
	t.Logf("real leaf bytes=%d legacy-response=%d transport-response=%d reduction=%.2f%% context=%s",
		len(payload), len(legacy), len(transport), 100*float64(len(legacy)-len(transport))/float64(len(legacy)), context.SID)
}

func TestCVLeafScalarTransportCompressionAbsorbsDuplicateACKOwnership(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	var unique, duplicated bytes.Buffer
	for i := range leaf.Receivers {
		ack := leaf.Receivers[i].ACK
		if ack == nil {
			t.Fatal("all-ACK fixture contains fallback receiver")
		}
		proof, err := cvOwnershipProofScalarCanonicalBytesAfterValidation(&ack.Ownership, context)
		if err != nil {
			t.Fatal(err)
		}
		_ = cvWriteBytes(&unique, proof)
		_ = cvWriteBytes(&duplicated, proof)
		_ = cvWriteBytes(&duplicated, proof)
	}
	compressedSize := func(input []byte, level int) int {
		var output bytes.Buffer
		writer, err := flate.NewWriter(&output, level)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(input); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return output.Len()
	}
	uniqueCompressed := compressedSize(unique.Bytes(), flate.DefaultCompression)
	duplicatedCompressed := compressedSize(duplicated.Bytes(), flate.DefaultCompression)
	duplicateRaw := duplicated.Len() - unique.Len()
	duplicateCompressed := duplicatedCompressed - uniqueCompressed
	t.Logf("ACK ownership duplicate raw=%d compressed_increment=%d absorption=%.2f%%",
		duplicateRaw, duplicateCompressed,
		100*(1-float64(duplicateCompressed)/float64(duplicateRaw)))
	if duplicateCompressed*20 >= duplicateRaw {
		t.Fatalf("DEFLATE retained at least 5%% of duplicate ownership bytes: raw=%d compressed=%d",
			duplicateRaw, duplicateCompressed)
	}
	payload, err := cvLeafScalarCanonicalBytesAfterValidation(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	defaultSize := compressedSize(payload, flate.DefaultCompression)
	bestSize := compressedSize(payload, flate.BestCompression)
	t.Logf("canonical leaf DEFLATE default=%d best=%d incremental_reduction=%.3f%%",
		defaultSize, bestSize, 100*float64(defaultSize-bestSize)/float64(defaultSize))
	if bestSize > defaultSize {
		t.Fatalf("best DEFLATE unexpectedly larger than default: default=%d best=%d", defaultSize, bestSize)
	}
}

func cvBuildMixedLeafScalarForTest(
	t *testing.T, context *cvLeafContextScalar, receivers *cvReceiverKeyMaterialScalar,
	validators *cvValidatorKeyMaterialScalar, fallbackIndex int,
) *cvLeafScalar {
	t.Helper()
	dealer := context.OldRoster[0]
	count := context.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, count)
	blindingCoefficients := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
	}
	commitments, coreProof, err := cvProveCoreScalar(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		t.Fatal(err)
	}
	offers := make([]*cvReceiverLaneOfferScalar, len(context.NewRoster))
	acks := make([]*cvACKEvidenceScalar, len(context.NewRoster))
	var fallbackOffer *cvReceiverLaneOfferScalar
	var fallbackWitness *cvDealerReceiverWitnessScalar
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialScalar(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialScalar(blindingCoefficients, index)
		var witness *cvDealerReceiverWitnessScalar
		offers[i], witness, err = cvEncryptReceiverLanesScalar(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			t.Fatal(err)
		}
		if index == fallbackIndex {
			fallbackOffer = offers[i]
			fallbackWitness = witness
			continue
		}
		acks[i], _, _, err = cvVerifyDecryptAndSignACKScalar(
			context, dealer, offers[i], &receivers.encryptionPublicKeys[i],
			receivers.localEncryptionSecrets[receiverID], receivers.identityPublicKeys[i],
			receivers.localIdentitySecrets[receiverID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	evidence, err := cvBuildFallbackEvidenceScalar(
		context, dealer, []*cvReceiverLaneOfferScalar{fallbackOffer},
		[]bls12381.G1Affine{receivers.encryptionPublicKeys[fallbackIndex-1]},
		[]*cvDealerReceiverWitnessScalar{fallbackWitness},
	)
	if err != nil {
		t.Fatal(err)
	}
	ackIndices := make([]int, 0, len(context.NewRoster)-1)
	for index := 1; index <= len(context.NewRoster); index++ {
		if index != fallbackIndex {
			ackIndices = append(ackIndices, index)
		}
	}
	leaf, err := cvBuildLeafScalar(
		context, dealer, commitments, coreProof, offers, acks,
		&cvEvidencePartitionScalar{ACKReceiverIndices: ackIndices, FallbackReceiverIndices: []int{fallbackIndex}},
		evidence, receivers, validators,
	)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
