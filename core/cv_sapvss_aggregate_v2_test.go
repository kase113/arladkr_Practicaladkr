package core

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVAggregateHeaderV2AndSelectionDigestAreCanonical(t *testing.T) {
	coin := &cvCoinOutputV2{Invocation: []byte("contributor invocation"), Certificate: []byte("threshold certificate"), Value: hashBytes([]byte("coin value"))}
	indices, err := cvSelectedPoolIndicesV2(5, 3, coin.Value)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := cvSelectionDigestV2(coin, indices, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	context := hashBytes([]byte("context"))
	pool := hashBytes([]byte("pool"))
	instance, err := cvAggregateInstanceDigestV2(context, 2, pool, selection)
	if err != nil {
		t.Fatal(err)
	}
	header := &cvAggregateHeaderV2{ContextDigest: context, ProposerID: 2, PoolDigest: pool, SelectionDigest: selection,
		AggregateDigest: hashBytes([]byte("aggregate")), PayloadDigest: hashBytes([]byte("payload")), APDBInstance: instance, APDBRoot: hashBytes([]byte("root"))}
	wire, err := cvAggregateHeaderV2CanonicalBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateHeaderV2(wire)
	if err != nil || !bytes.Equal(decoded.APDBInstance, instance) {
		t.Fatalf("aggregate header V2 codec: %v", err)
	}
	bad := append([]int(nil), indices...)
	bad[0], bad[1] = bad[1], bad[0]
	if _, err := cvSelectionDigestV2(coin, bad, 5, 3); err == nil {
		t.Fatal("accepted a reordered contributor selection")
	}
	mutated := *header
	mutated.SelectionDigest = append([]byte(nil), header.SelectionDigest...)
	mutated.SelectionDigest[0] ^= 1
	if _, err := cvAggregateHeaderV2CanonicalBytes(&mutated); err == nil {
		t.Fatal("accepted aggregate header with an unrelated APDB instance")
	}
}

func TestCVAggV2BuildCodecAndRecomputeVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 aggregate proof test in short mode")
	}
	first, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	params, err := cvDeriveV2Params(cvV2ParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.componentCount; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, context.OldRoster[i], context, receivers, validators))
	}
	aggregate, err := cvAggV2(leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cvAggregateV2CanonicalBytes(aggregate, context, params)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateV2(payload, context, params)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := cvAVerV2(payload, leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, aggregate.Digest) || !bytes.Equal(verified.Digest, aggregate.Digest) {
		t.Fatal("CV V2 aggregate codec changed its digest")
	}

	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		t.Fatal(err)
	}
	poolDigest := hashBytes([]byte("aggregate pool"))
	selectionDigest := hashBytes([]byte("aggregate selection"))
	instance, err := cvAggregateInstanceDigestV2(contextDigest, context.OldRoster[0], poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := cvAggregatePayloadDigestV2(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := &cvAggregateHeaderV2{
		ContextDigest: contextDigest, ProposerID: context.OldRoster[0], PoolDigest: poolDigest,
		SelectionDigest: selectionDigest, AggregateDigest: aggregate.Digest, PayloadDigest: payloadDigest,
		APDBInstance: instance, APDBRoot: hashBytes([]byte("aggregate APDB root")),
	}
	if err := cvVerifyAggregateHeaderPayloadV2(header, payload, aggregate); err != nil {
		t.Fatal(err)
	}
	badHeader := *header
	badHeader.PayloadDigest = hashBytes([]byte("wrong payload"))
	if err := cvVerifyAggregateHeaderPayloadV2(&badHeader, payload, aggregate); err == nil {
		t.Fatal("accepted aggregate header with wrong payload digest")
	}

	reordered := append([]*cvLeafV2(nil), leaves...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := cvAVerV2(payload, reordered, context, params, receivers, validators); err == nil {
		t.Fatal("accepted aggregate payload for reordered selected components")
	}
	duplicate := append([]*cvLeafV2(nil), leaves...)
	duplicate[1] = duplicate[0]
	if _, err := cvAggV2(duplicate, context, params, receivers, validators); err == nil {
		t.Fatal("accepted duplicate aggregate dealer")
	}
	if _, err := cvDecodeAggregateV2(append(append([]byte(nil), payload...), 0), context, params); err == nil {
		t.Fatal("accepted aggregate payload with trailing bytes")
	}
	badEvaluation := *decoded
	badEvaluation.Components = append([]cvAggregateComponentV2(nil), decoded.Components...)
	badEvaluation.CoefficientCommitments = append([]bls12381.G1Affine(nil), decoded.CoefficientCommitments...)
	badEvaluation.Receivers = append([]cvAggregateReceiverV2(nil), decoded.Receivers...)
	badEvaluation.Receivers[0] = decoded.Receivers[0]
	badEvaluation.Receivers[0].Evaluation.Add(&badEvaluation.Receivers[0].Evaluation, &genG1)
	badUnsigned, err := cvAggregateV2UnsignedCanonicalBytesAfterValidation(&badEvaluation, context, params)
	if err != nil {
		t.Fatal(err)
	}
	badEvaluation.Digest = hashBytes([]byte(cvAggregateDigestV2Domain), badUnsigned)
	badWire, err := cvAggregateV2CanonicalBytesAfterValidation(&badEvaluation, context, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeAggregateV2(badWire, context, params); err == nil {
		t.Fatal("decoded aggregate accepted a digest-resigned evaluation mutation")
	}
	mutatedLeaf := *leaves[0]
	mutatedLeaf.Digest = append([]byte(nil), leaves[0].Digest...)
	mutatedLeaf.Digest[0] ^= 1
	badLeaves := append([]*cvLeafV2(nil), leaves...)
	badLeaves[0] = &mutatedLeaf
	if _, err := cvAVerV2(payload, badLeaves, context, params, receivers, validators); err == nil {
		t.Fatal("accepted aggregate with an invalid selected leaf")
	}
}

func TestCVV2AggregateFitsEpochShardUpperBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 aggregate sizing test in short mode")
	}
	first, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	params, err := cvDeriveV2Params(cvV2ParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.componentCount; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, context.OldRoster[i], context, receivers, validators))
	}
	aggregate, err := cvAggV2(leaves, context, params, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cvAggregateV2CanonicalBytes(aggregate, context, params)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if want := cvAggregateWireSizeV2(context, params, chunks); len(payload) != want {
		t.Fatalf("aggregate V2 sizing mismatch: got=%d want=%d", len(payload), want)
	}
	shardBytes, err := cvEpochShardBytesUpperBoundV2(
		context, params, receivers, validators, params.recoveryThreshold,
	)
	if err != nil {
		t.Fatal(err)
	}
	if 8+len(payload) > params.recoveryThreshold*shardBytes {
		t.Fatalf("aggregate exceeds epoch shard capacity: payload=%d shard=%d", len(payload), shardBytes)
	}
}

func cvBuildAllACKLeafForDealerV2(
	t *testing.T, dealer int, context *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) *cvLeafV2 {
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
	commitments, coreProof, err := cvProveCoreV2(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		t.Fatal(err)
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
	return leaf
}
