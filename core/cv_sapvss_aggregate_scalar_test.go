package core

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVAggregateHeaderScalarAndSelectionDigestAreCanonical(t *testing.T) {
	coin := &cvCoinOutputScalar{Invocation: []byte("contributor invocation"), Certificate: []byte("threshold certificate"), Value: hashBytes([]byte("coin value"))}
	indices, err := cvSelectedPoolIndicesScalar(5, 3, coin.Value)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := cvSelectionDigestScalar(coin, indices, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	context := hashBytes([]byte("context"))
	pool := hashBytes([]byte("pool"))
	instance, err := cvAggregateInstanceDigestScalar(context, 2, pool, selection)
	if err != nil {
		t.Fatal(err)
	}
	header := &cvAggregateHeaderScalar{ContextDigest: context, ProposerID: 2, PoolDigest: pool, SelectionDigest: selection,
		AggregateDigest: hashBytes([]byte("aggregate")), PayloadDigest: hashBytes([]byte("payload")), APDBInstance: instance, APDBRoot: hashBytes([]byte("root"))}
	wire, err := cvAggregateHeaderScalarCanonicalBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateHeaderScalar(wire)
	if err != nil || !bytes.Equal(decoded.APDBInstance, instance) {
		t.Fatalf("aggregate header V2 codec: %v", err)
	}
	bad := append([]int(nil), indices...)
	bad[0], bad[1] = bad[1], bad[0]
	if _, err := cvSelectionDigestScalar(coin, bad, 5, 3); err == nil {
		t.Fatal("accepted a reordered contributor selection")
	}
	mutated := *header
	mutated.SelectionDigest = append([]byte(nil), header.SelectionDigest...)
	mutated.SelectionDigest[0] ^= 1
	if _, err := cvAggregateHeaderScalarCanonicalBytes(&mutated); err == nil {
		t.Fatal("accepted aggregate header with an unrelated APDB instance")
	}
}

func TestCVAggScalarBuildCodecAndRecomputeVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 aggregate proof test in short mode")
	}
	first, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	params, err := cvDeriveScalarParams(cvScalarParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafScalar{first}
	for i := 1; i < params.componentCount; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerScalar(t, context.OldRoster[i], context, receivers, validators))
	}
	aggregate, err := cvAggScalar(leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cvAggregateScalarCanonicalBytes(aggregate, context, params)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateScalar(payload, context, params)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := cvAVerScalar(payload, leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, aggregate.Digest) || !bytes.Equal(verified.Digest, aggregate.Digest) {
		t.Fatal("CV V2 aggregate codec changed its digest")
	}

	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		t.Fatal(err)
	}
	poolDigest := hashBytes([]byte("aggregate pool"))
	selectionDigest := hashBytes([]byte("aggregate selection"))
	instance, err := cvAggregateInstanceDigestScalar(contextDigest, context.OldRoster[0], poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := cvAggregatePayloadDigestScalar(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := &cvAggregateHeaderScalar{
		ContextDigest: contextDigest, ProposerID: context.OldRoster[0], PoolDigest: poolDigest,
		SelectionDigest: selectionDigest, AggregateDigest: aggregate.Digest, PayloadDigest: payloadDigest,
		APDBInstance: instance, APDBRoot: hashBytes([]byte("aggregate APDB root")),
	}
	if err := cvVerifyAggregateHeaderPayloadScalar(header, payload, aggregate); err != nil {
		t.Fatal(err)
	}
	badHeader := *header
	badHeader.PayloadDigest = hashBytes([]byte("wrong payload"))
	if err := cvVerifyAggregateHeaderPayloadScalar(&badHeader, payload, aggregate); err == nil {
		t.Fatal("accepted aggregate header with wrong payload digest")
	}

	reordered := append([]*cvLeafScalar(nil), leaves...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := cvAVerScalar(payload, reordered, context, params, receivers, validators); err == nil {
		t.Fatal("accepted aggregate payload for reordered selected components")
	}
	duplicate := append([]*cvLeafScalar(nil), leaves...)
	duplicate[1] = duplicate[0]
	if _, err := cvAggScalar(duplicate, context, params, receivers, validators); err == nil {
		t.Fatal("accepted duplicate aggregate dealer")
	}
	if _, err := cvDecodeAggregateScalar(append(append([]byte(nil), payload...), 0), context, params); err == nil {
		t.Fatal("accepted aggregate payload with trailing bytes")
	}
	badEvaluation := *decoded
	badEvaluation.Components = append([]cvAggregateComponentScalar(nil), decoded.Components...)
	badEvaluation.CoefficientCommitments = append([]bls12381.G1Affine(nil), decoded.CoefficientCommitments...)
	badEvaluation.Receivers = append([]cvAggregateReceiverScalar(nil), decoded.Receivers...)
	badEvaluation.Receivers[0] = decoded.Receivers[0]
	badEvaluation.Receivers[0].Evaluation.Add(&badEvaluation.Receivers[0].Evaluation, &genG1)
	badUnsigned, err := cvAggregateScalarUnsignedCanonicalBytesAfterValidation(&badEvaluation, context, params)
	if err != nil {
		t.Fatal(err)
	}
	badEvaluation.Digest = hashBytes([]byte(cvAggregateDigestScalarDomain), badUnsigned)
	badWire, err := cvAggregateScalarCanonicalBytesAfterValidation(&badEvaluation, context, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeAggregateScalar(badWire, context, params); err == nil {
		t.Fatal("decoded aggregate accepted a digest-resigned evaluation mutation")
	}
	mutatedLeaf := *leaves[0]
	mutatedLeaf.Digest = append([]byte(nil), leaves[0].Digest...)
	mutatedLeaf.Digest[0] ^= 1
	badLeaves := append([]*cvLeafScalar(nil), leaves...)
	badLeaves[0] = &mutatedLeaf
	if _, err := cvAVerScalar(payload, badLeaves, context, params, receivers, validators); err == nil {
		t.Fatal("accepted aggregate with an invalid selected leaf")
	}
}

func TestCVScalarAggregateFitsEpochShardUpperBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 aggregate sizing test in short mode")
	}
	first, context, receivers, validators := cvAllACKLeafScalarFixture(t)
	params, err := cvDeriveScalarParams(cvScalarParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafScalar{first}
	for i := 1; i < params.componentCount; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerScalar(t, context.OldRoster[i], context, receivers, validators))
	}
	aggregate, err := cvAggScalar(leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cvAggregateScalarCanonicalBytes(aggregate, context, params)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if want := cvAggregateWireSizeScalar(context, params, chunks); len(payload) != want {
		t.Fatalf("aggregate V2 sizing mismatch: got=%d want=%d", len(payload), want)
	}
	shardBytes, err := cvEpochShardBytesUpperBoundScalar(
		context, params, receivers, validators, params.recoveryThreshold,
	)
	if err != nil {
		t.Fatal(err)
	}
	if 8+len(payload) > params.recoveryThreshold*shardBytes {
		t.Fatalf("aggregate exceeds epoch shard capacity: payload=%d shard=%d", len(payload), shardBytes)
	}
}

func cvBuildAllACKLeafForDealerScalar(
	t *testing.T, dealer int, context *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) *cvLeafScalar {
	t.Helper()
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
	for i, receiverID := range context.NewRoster {
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
	return leaf
}
