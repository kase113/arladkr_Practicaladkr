package core

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVScalarShareV2ProofCodecAndThresholdRecovery(t *testing.T) {
	aggregate, context, params, receivers := cvAggregateForShareV2Fixture(t)
	outputs := make([]*cvScalarShareOutputV2, len(context.NewRoster))
	scalars := make([]fr.Element, len(context.NewRoster))
	for i, receiverID := range context.NewRoster {
		var err error
		scalars[i], outputs[i], err = cvDecryptAggregateShareV2(
			aggregate, context, params, receiverID, i+1, &receivers.encryptionPublicKeys[i],
			receivers.localEncryptionSecrets[receiverID],
		)
		if err != nil {
			t.Fatalf("decrypt aggregate share %d: %v", i+1, err)
		}
		if want := cvPointTimes(&genG1, &scalars[i]); !want.Equal(&outputs[i].Y) {
			t.Fatalf("local scalar %d does not match public share", i+1)
		}
		if err := cvVerifyAggregateShareV2(
			outputs[i], aggregate, context, params, &receivers.encryptionPublicKeys[i],
		); err != nil {
			t.Fatalf("verify aggregate share %d: %v", i+1, err)
		}
	}
	wire, err := cvScalarShareOutputV2CanonicalBytes(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeScalarShareOutputV2(wire, aggregate, context, params, receivers)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Y.Equal(&outputs[0].Y) || !decoded.YBlind.Equal(&outputs[0].YBlind) {
		t.Fatal("CV V2 aggregate-share codec changed public shares")
	}
	if _, err := cvDecodeScalarShareOutputV2(append(append([]byte(nil), wire...), 0), aggregate, context, params, receivers); err == nil {
		t.Fatal("accepted CV V2 aggregate-share output with trailing bytes")
	}

	firstKey, err := cvRecoverThresholdPublicKeyV2(outputs[:params.newShareThreshold], aggregate, context, params, receivers)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := cvRecoverThresholdPublicKeyV2(outputs[1:], aggregate, context, params, receivers)
	if err != nil {
		t.Fatal(err)
	}
	if !firstKey.Equal(&secondKey) {
		t.Fatal("valid CV V2 aggregate-share subsets produced different public keys")
	}
	if _, err := cvRecoverThresholdPublicKeyV2(outputs[:params.newShareThreshold-1], aggregate, context, params, receivers); err == nil {
		t.Fatal("recovered CV V2 public key below threshold")
	}
	duplicate := []*cvScalarShareOutputV2{outputs[0], outputs[0], outputs[2]}
	if _, err := cvRecoverThresholdPublicKeyV2(duplicate, aggregate, context, params, receivers); err == nil {
		t.Fatal("accepted duplicate CV V2 aggregate-share receiver")
	}

	var wrongSecret fr.Element
	wrongSecret.SetOne()
	if _, _, err := cvDecryptAggregateShareV2(
		aggregate, context, params, context.NewRoster[0], 1, &receivers.encryptionPublicKeys[0], wrongSecret,
	); err == nil {
		t.Fatal("accepted wrong CV V2 aggregate-share decryption secret")
	}

	compensated := *outputs[0]
	compensated.Y.Add(&compensated.Y, &genG1)
	compensated.YBlind.Sub(&compensated.YBlind, &genG1)
	if err := cvVerifyAggregateShareV2(&compensated, aggregate, context, params, &receivers.encryptionPublicKeys[0]); err == nil {
		t.Fatal("accepted compensated CV V2 aggregate-share openings without a fresh proof")
	}
	badResponse := *outputs[0]
	var one fr.Element
	one.SetOne()
	badResponse.Proof.KeyResponse.Add(&badResponse.Proof.KeyResponse, &one)
	if err := cvVerifyAggregateShareV2(&badResponse, aggregate, context, params, &receivers.encryptionPublicKeys[0]); err == nil {
		t.Fatal("accepted mutated CV V2 aggregate-share response")
	}
	badScalarResponse := *outputs[0]
	badScalarResponse.Proof.ScalarResponse.Add(&badScalarResponse.Proof.ScalarResponse, &one)
	if err := cvVerifyAggregateShareV2(&badScalarResponse, aggregate, context, params, &receivers.encryptionPublicKeys[0]); err == nil {
		t.Fatal("accepted mutated CV V2 scalar-knowledge response")
	}
	var wrongReceiverSecret fr.Element
	if _, err := wrongReceiverSecret.SetRandom(); err != nil {
		t.Fatal(err)
	}
	wrongReceiverKey, err := cvReceiverPublicKey(wrongReceiverSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyAggregateShareV2(outputs[0], aggregate, context, params, &wrongReceiverKey); err == nil {
		t.Fatal("accepted CV V2 aggregate-share proof under another receiver key")
	}

	badBlindingAggregate := cvCloneAggregateForShareV2(aggregate)
	badBlindingAggregate.Receivers[0].Blinding.c.Add(&badBlindingAggregate.Receivers[0].Blinding.c, &genG1)
	unsigned, err := cvAggregateV2UnsignedCanonicalBytes(badBlindingAggregate, context, params)
	if err != nil {
		t.Fatal(err)
	}
	badBlindingAggregate.Digest = hashBytes([]byte(cvAggregateDigestV2Domain), unsigned)
	replayedBlinding := *outputs[0]
	replayedBlinding.AggregateDigest = append([]byte(nil), badBlindingAggregate.Digest...)
	if err := cvVerifyAggregateShareV2(
		&replayedBlinding, badBlindingAggregate, context, params, &receivers.encryptionPublicKeys[0],
	); err == nil {
		t.Fatal("replayed CV V2 aggregate-share proof after blinding ciphertext mutation")
	}

	outOfRange := cvCloneAggregateForShareV2(aggregate)
	_, bound, _, err := cvProfile(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	var excessivePoint = genG1
	excessivePoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(bound+1))
	outOfRange.Receivers[0].ScalarChunks[0].c.Add(
		&outOfRange.Receivers[0].ScalarChunks[0].c, &excessivePoint,
	)
	unsigned, err = cvAggregateV2UnsignedCanonicalBytes(outOfRange, context, params)
	if err != nil {
		t.Fatal(err)
	}
	outOfRange.Digest = hashBytes([]byte(cvAggregateDigestV2Domain), unsigned)
	replayed := *outputs[0]
	replayed.AggregateDigest = append([]byte(nil), outOfRange.Digest...)
	if err := cvVerifyAggregateShareV2(
		&replayed, outOfRange, context, params, &receivers.encryptionPublicKeys[0],
	); err == nil {
		t.Fatal("replayed CV V2 aggregate-share proof onto mutated ciphertext lanes")
	}
	if _, _, err := cvDecryptAggregateShareV2(
		outOfRange, context, params, context.NewRoster[0], 1, &receivers.encryptionPublicKeys[0],
		receivers.localEncryptionSecrets[context.NewRoster[0]],
	); err == nil {
		t.Fatal("accepted CV V2 aggregate digit above K(B-1)")
	}

	wrongDegree := *context
	wrongDegree.SharingDegree--
	if _, _, err := cvDecryptAggregateShareV2(
		aggregate, &wrongDegree, params, wrongDegree.NewRoster[0], 1, &receivers.encryptionPublicKeys[0],
		receivers.localEncryptionSecrets[wrongDegree.NewRoster[0]],
	); err == nil {
		t.Fatal("accepted CV V2 aggregate share with wrong protocol degree")
	}
}

func TestCVCompletedScalarExchangeRepliesToLatePeer(t *testing.T) {
	aggregate, leafContext, params, receivers := cvAggregateForShareV2Fixture(t)
	outputs := make([]*cvScalarShareOutputV2, 2)
	for i := range outputs {
		var err error
		receiverID := leafContext.NewRoster[i]
		_, outputs[i], err = cvDecryptAggregateShareV2(
			aggregate, leafContext, params, receiverID, i+1,
			&receivers.encryptionPublicKeys[i], receivers.localEncryptionSecrets[receiverID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	localWire, err := cvScalarShareOutputV2CanonicalBytes(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	peerWire, err := cvScalarShareOutputV2CanonicalBytes(outputs[1])
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := string(aggregate.Digest)
	service := &cvAPDBNetworkServiceV2{
		ctx: ctx,
		cfg: cvAPDBNetworkServiceConfigV2{
			LeafContext: leafContext, Receivers: receivers, Params: params,
		},
		localScalarOutputs:  map[string][]byte{key: localWire},
		scalarAggregates:    map[string]*cvAggregateV2{key: aggregate},
		pendingScalarShares: make(map[string]*cvPendingScalarSharesV2),
		outbound:            make(chan cvOutboundMessageV2, 1),
	}
	service.handleAggregateShare(Message{From: outputs[1].ReceiverID, Body: peerWire})
	select {
	case reply := <-service.outbound:
		if reply.to != outputs[1].ReceiverID || reply.tag != cvTagAggregateShareV2 || !bytes.Equal(reply.payload, localWire) {
			t.Fatal("completed scalar exchange returned the wrong late-peer reply")
		}
	default:
		t.Fatal("completed scalar exchange did not reply to a valid late peer")
	}

	mutated := append([]byte(nil), peerWire...)
	mutated[len(mutated)-1] ^= 1
	service.handleAggregateShare(Message{From: outputs[1].ReceiverID, Body: mutated})
	select {
	case <-service.outbound:
		t.Fatal("completed scalar exchange replied to an invalid late-peer share")
	default:
	}

	pending := &cvPendingScalarSharesV2{
		aggregate: aggregate,
		outputs:   map[int]*cvScalarShareOutputV2{outputs[1].ReceiverID: outputs[1]},
		wires:     map[int][]byte{outputs[1].ReceiverID: append([]byte(nil), peerWire...)},
		ready:     make(chan struct{}, 1),
	}
	service.pendingScalarShares[key] = pending
	service.handleAggregateShare(Message{From: outputs[1].ReceiverID, Body: peerWire})
	select {
	case reply := <-service.outbound:
		if !bytes.Equal(reply.payload, localWire) {
			t.Fatal("exact scalar-share retry returned the wrong local share")
		}
	default:
		t.Fatal("exact scalar-share retry did not use the verified-wire fast path")
	}
	service.handleAggregateShare(Message{From: outputs[1].ReceiverID, Body: mutated})
	select {
	case <-service.outbound:
		t.Fatal("mutated scalar-share retry used the exact-wire fast path")
	default:
	}
}

func cvAggregateForShareV2Fixture(
	t *testing.T,
) (*cvAggregateV2, *cvLeafContextV2, cvV2Params, *cvReceiverKeyMaterialV2) {
	t.Helper()
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
	return aggregate, context, params, receivers
}

func cvCloneAggregateForShareV2(aggregate *cvAggregateV2) *cvAggregateV2 {
	cloned := *aggregate
	cloned.ContextDigest = append([]byte(nil), aggregate.ContextDigest...)
	cloned.Digest = append([]byte(nil), aggregate.Digest...)
	cloned.Components = append([]cvAggregateComponentV2(nil), aggregate.Components...)
	for i := range cloned.Components {
		cloned.Components[i].LeafDigest = append([]byte(nil), aggregate.Components[i].LeafDigest...)
	}
	cloned.CoefficientCommitments = append([]bls12381.G1Affine(nil), aggregate.CoefficientCommitments...)
	cloned.Receivers = append([]cvAggregateReceiverV2(nil), aggregate.Receivers...)
	for i := range cloned.Receivers {
		cloned.Receivers[i].ScalarChunks = append(
			[]cvElGamalCiphertext(nil), aggregate.Receivers[i].ScalarChunks...,
		)
		cloned.Receivers[i].Blinding = aggregate.Receivers[i].Blinding
	}
	return &cloned
}
