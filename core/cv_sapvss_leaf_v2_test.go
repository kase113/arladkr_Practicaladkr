package core

import (
	"bytes"
	"compress/flate"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvAllACKLeafV2Fixture(
	t *testing.T,
) (*cvLeafV2, *cvLeafContextV2, *cvReceiverKeyMaterialV2, *cvValidatorKeyMaterialV2) {
	t.Helper()
	cfg := cvV2ParamsTestConfig()
	receiverPublicDir := filepath.Join(t.TempDir(), "receiver-public")
	receiverSecretDir := filepath.Join(t.TempDir(), "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(
		receiverPublicDir, receiverSecretDir, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee,
	); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryV2(
		receiverPublicDir, receiverSecretDir, cfg.SID, uint64(cfg.Epoch),
		cfg.NewCommittee, cfg.NewCommittee,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatorPublicDir := filepath.Join(t.TempDir(), "validator-public")
	validatorSecretDir := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryV2(
		validatorPublicDir, validatorSecretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee,
	); err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryV2(
		validatorPublicDir, validatorSecretDir, cfg.SID, uint64(cfg.Epoch),
		cfg.OldCommittee, cfg.OldCommittee,
	)
	if err != nil {
		t.Fatal(err)
	}
	context := &cvLeafContextV2{
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
	commitments, coreProof, err := cvProveCoreV2(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		t.Fatal(err)
	}
	offers := make([]*cvReceiverLaneOfferV2, len(cfg.NewCommittee))
	acks := make([]*cvACKEvidenceV2, len(cfg.NewCommittee))
	for i, receiverID := range cfg.NewCommittee {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		offers[i], _, err = cvEncryptReceiverLanesV2(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			t.Fatal(err)
		}
		acks[i], _, _, err = cvVerifyDecryptAndSignACKV2(
			context, dealer, offers[i], &receivers.encryptionPublicKeys[i],
			receivers.localEncryptionSecrets[receiverID], receivers.identityPublicKeys[i],
			receivers.localIdentitySecrets[receiverID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	leaf, err := cvBuildAllACKLeafV2(
		context, dealer, commitments, coreProof, offers, acks, receivers, validators,
	)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, context, receivers, validators
}

func TestCVAllACKLeafV2BuildVerifyAndCodec(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	if err := cvVerifyAPVSSV2(leaf, context, receivers, validators); err != nil {
		t.Fatalf("verify all-ACK V2 leaf: %v", err)
	}
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	wantWireBytes, err := cvLeafWireSizeV2(context, chunks, 0)
	if err != nil || len(wire) != wantWireBytes {
		t.Fatalf("all-ACK V2 leaf sizing mismatch: got=%d want=%d err=%v", len(wire), wantWireBytes, err)
	}
	decoded, err := cvDecodeLeafV2(wire, context, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, leaf.Digest) ||
		cvVerifyAPVSSV2(decoded, context, receivers, validators) != nil {
		t.Fatal("decoded all-ACK V2 leaf did not verify")
	}
	if _, err := cvDecodeLeafV2(append(append([]byte(nil), wire...), 0),
		context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with trailing bytes")
	}
}

func TestCVReceiverEvaluationBatchV2MatchesExactVerification(t *testing.T) {
	leaf, context, _, _ := cvAllACKLeafV2Fixture(t)
	evaluations := make([]bls12381.G1Affine, len(leaf.Receivers))
	for index := range leaf.Receivers {
		evaluations[index] = leaf.Receivers[index].Offer.Evaluation
	}
	if err := cvVerifyReceiverEvaluationsExactV2(leaf.CoefficientCommitments, evaluations); err != nil {
		t.Fatalf("exact receiver evaluation verification: %v", err)
	}
	for _, validatePoints := range []bool{true, false} {
		if err := cvVerifyReceiverEvaluationsBatchV2(
			context, leaf.DealerID, leaf.CoefficientCommitments, evaluations, validatePoints,
		); err != nil {
			t.Fatalf("batch receiver evaluation verification validate_points=%t: %v", validatePoints, err)
		}
	}

	mutated := append([]bls12381.G1Affine(nil), evaluations...)
	mutated[len(mutated)-1].Add(&mutated[len(mutated)-1], &genG1)
	if err := cvVerifyReceiverEvaluationsBatchV2(
		context, leaf.DealerID, leaf.CoefficientCommitments, mutated, false,
	); err == nil {
		t.Fatal("batch receiver evaluation verification accepted a mutated evaluation")
	}
}

func TestCVOwnershipBatchV2MatchesExactAndRejectsMutations(t *testing.T) {
	leaf, context, receivers, _ := cvAllACKLeafV2Fixture(t)
	offers := make([]*cvReceiverLaneOfferV2, len(leaf.Receivers))
	keys := append([]bls12381.G1Affine(nil), receivers.encryptionPublicKeys...)
	for i := range leaf.Receivers {
		offers[i] = &leaf.Receivers[i].Offer
		if err := cvVerifyOwnershipV2(context, leaf.DealerID, offers[i], &keys[i]); err != nil {
			t.Fatalf("exact ownership verification receiver %d: %v", i+1, err)
		}
	}
	for _, validatePoints := range []bool{true, false} {
		if err := cvVerifyOwnershipBatchV2(
			context, leaf.DealerID, offers, keys, validatePoints,
		); err != nil {
			t.Fatalf("batch ownership verification validate_points=%t: %v", validatePoints, err)
		}
	}

	mutations := []struct {
		name   string
		mutate func(*cvReceiverLaneOfferV2)
	}{
		{
			name: "commitment",
			mutate: func(offer *cvReceiverLaneOfferV2) {
				offer.Ownership.ScalarCoinCommitments[0].Add(
					&offer.Ownership.ScalarCoinCommitments[0], &genG1,
				)
			},
		},
		{
			name: "response",
			mutate: func(offer *cvReceiverLaneOfferV2) {
				var one fr.Element
				one.SetOne()
				offer.Ownership.BlindingShareResponse.Add(
					&offer.Ownership.BlindingShareResponse, &one,
				)
			},
		},
		{
			name: "ciphertext",
			mutate: func(offer *cvReceiverLaneOfferV2) {
				offer.ScalarChunks[0].c.Add(&offer.ScalarChunks[0].c, &genG1)
			},
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutatedOffers := append([]*cvReceiverLaneOfferV2(nil), offers...)
			mutatedOffers[len(mutatedOffers)-1] = cvCloneReceiverLaneOfferV2(
				offers[len(offers)-1],
			)
			mutation.mutate(mutatedOffers[len(mutatedOffers)-1])
			if err := cvVerifyOwnershipBatchV2(
				context, leaf.DealerID, mutatedOffers, keys, false,
			); err == nil {
				t.Fatal("batch ownership verification accepted a mutation")
			}
		})
	}
}

func TestCVAllACKLeafV2RejectsCryptographicMutations(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)

	badEvaluation := *leaf
	badEvaluation.Receivers = append([]cvLeafReceiverV2(nil), leaf.Receivers...)
	badEvaluation.Receivers[0] = leaf.Receivers[0]
	badEvaluation.Receivers[0].Offer = *cvCloneReceiverLaneOfferV2(&leaf.Receivers[0].Offer)
	badEvaluation.Receivers[0].Offer.Evaluation.Add(
		&badEvaluation.Receivers[0].Offer.Evaluation, &genG1,
	)
	if err := cvVerifyAPVSSV2(&badEvaluation, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with wrong polynomial evaluation")
	}

	badACK := *leaf
	badACK.Receivers = append([]cvLeafReceiverV2(nil), leaf.Receivers...)
	badACK.Receivers[0] = leaf.Receivers[0]
	badACK.Receivers[0].ACK = &cvACKEvidenceV2{
		Ownership: cvCloneOwnershipProofV2(&leaf.Receivers[0].ACK.Ownership),
		Signature: append([]byte(nil), leaf.Receivers[0].ACK.Signature...),
	}
	badACK.Receivers[0].ACK.Signature[0] ^= 1
	if err := cvVerifyAPVSSV2(&badACK, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated ACK")
	}

	badDealer := *leaf
	badDealer.DealerSignature = append([]byte(nil), leaf.DealerSignature...)
	badDealer.DealerSignature[0] ^= 1
	if err := cvVerifyAPVSSV2(&badDealer, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated dealer signature")
	}

	badDigest := *leaf
	badDigest.Digest = append([]byte(nil), leaf.Digest...)
	badDigest.Digest[0] ^= 1
	if err := cvVerifyAPVSSV2(&badDigest, context, receivers, validators); err == nil {
		t.Fatal("accepted V2 leaf with mutated digest")
	}
}

func TestCVLeafV2DecodedPathRejectsResignedOwnershipMutation(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	mutated := *leaf
	mutated.Receivers = append([]cvLeafReceiverV2(nil), leaf.Receivers...)
	mutated.Receivers[0] = leaf.Receivers[0]
	mutated.Receivers[0].Offer = *cvCloneReceiverLaneOfferV2(&leaf.Receivers[0].Offer)
	mutated.Receivers[0].Offer.Ownership.ScalarCipherCommitments[0].Add(
		&mutated.Receivers[0].Offer.Ownership.ScalarCipherCommitments[0], &genG1,
	)
	mutated.Receivers[0].ACK = &cvACKEvidenceV2{
		Ownership: cvCloneOwnershipProofV2(&mutated.Receivers[0].Offer.Ownership),
		Signature: append([]byte(nil), leaf.Receivers[0].ACK.Signature...),
	}
	unsigned, err := cvLeafV2UnsignedCanonicalBytesAfterValidation(&mutated, receivers)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := validators.localSecrets[mutated.DealerID]
	if !ok {
		t.Fatal("missing dealer signing secret")
	}
	mutated.DealerSignature, err = cvSignValidatorV2(
		secret, cvDealerSignatureDomainV2, hashBytes([]byte(cvDealerSignatureDomainV2), unsigned),
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafV2CanonicalBytesAfterValidation(&mutated, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeLeafV2(wire, context, receivers, validators); err == nil {
		t.Fatal("decoded V2 path accepted a resigned ownership-proof mutation")
	}
}

func TestCVLeafV2MixedACKFallbackBuildVerifyAndCodec(t *testing.T) {
	_, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	fallbackIndex := 1
	mixed := cvBuildMixedLeafV2ForTest(t, context, receivers, validators, fallbackIndex)
	if err := cvVerifyAPVSSV2(mixed, context, receivers, validators); err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafV2CanonicalBytes(mixed, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	wantWireBytes, err := cvLeafWireSizeV2(context, chunks, 1)
	if err != nil || len(wire) != wantWireBytes {
		t.Fatalf("mixed V2 leaf sizing mismatch: got=%d want=%d err=%v", len(wire), wantWireBytes, err)
	}
	decoded, err := cvDecodeLeafV2(wire, context, receivers, validators)
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
	if err := cvVerifyAPVSSV2(&bad, context, receivers, validators); err == nil {
		t.Fatal("accepted mixed CV V2 leaf with mutated fallback range proof")
	}
}

func TestCVLeafV2TransportCompressionUsesRealCanonicalLeaf(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	payload, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	instance := hashBytes([]byte("real canonical leaf transport compression"))
	legacy, err := cvAPDBPayloadResponseV2CanonicalBytes(&cvAPDBPayloadResponseV2{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := cvAPDBPayloadResponseV2TransportBytes(&cvAPDBPayloadResponseV2{
		InstanceDigest: instance, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAPDBPayloadResponseV2(transport, len(payload))
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("real leaf transport compression round trip: err=%v", err)
	}
	t.Logf("real leaf bytes=%d legacy-response=%d transport-response=%d reduction=%.2f%% context=%s",
		len(payload), len(legacy), len(transport), 100*float64(len(legacy)-len(transport))/float64(len(legacy)), context.SID)
}

func TestCVLeafV2TransportCompressionAbsorbsDuplicateACKOwnership(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	var unique, duplicated bytes.Buffer
	for i := range leaf.Receivers {
		ack := leaf.Receivers[i].ACK
		if ack == nil {
			t.Fatal("all-ACK fixture contains fallback receiver")
		}
		proof, err := cvOwnershipProofV2CanonicalBytesAfterValidation(&ack.Ownership, context)
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
	payload, err := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
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

func cvBuildMixedLeafV2ForTest(
	t *testing.T, context *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
	validators *cvValidatorKeyMaterialV2, fallbackIndex int,
) *cvLeafV2 {
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
	commitments, coreProof, err := cvProveCoreV2(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		t.Fatal(err)
	}
	offers := make([]*cvReceiverLaneOfferV2, len(context.NewRoster))
	acks := make([]*cvACKEvidenceV2, len(context.NewRoster))
	var fallbackOffer *cvReceiverLaneOfferV2
	var fallbackWitness *cvDealerReceiverWitnessV2
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		var witness *cvDealerReceiverWitnessV2
		offers[i], witness, err = cvEncryptReceiverLanesV2(
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
		acks[i], _, _, err = cvVerifyDecryptAndSignACKV2(
			context, dealer, offers[i], &receivers.encryptionPublicKeys[i],
			receivers.localEncryptionSecrets[receiverID], receivers.identityPublicKeys[i],
			receivers.localIdentitySecrets[receiverID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	evidence, err := cvBuildFallbackEvidenceV2(
		context, dealer, []*cvReceiverLaneOfferV2{fallbackOffer},
		[]bls12381.G1Affine{receivers.encryptionPublicKeys[fallbackIndex-1]},
		[]*cvDealerReceiverWitnessV2{fallbackWitness},
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
	leaf, err := cvBuildLeafV2(
		context, dealer, commitments, coreProof, offers, acks,
		&cvEvidencePartitionV2{ACKReceiverIndices: ackIndices, FallbackReceiverIndices: []int{fallbackIndex}},
		evidence, receivers, validators,
	)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
