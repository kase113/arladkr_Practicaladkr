package core

import (
	"bytes"
	"testing"
)

func TestAPVSSLeafPrototypeCodecRoundTripV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	for _, profile := range []struct {
		name     string
		fallback []int
	}{
		{name: "I_empty"},
		{name: "I_1", fallback: []int{1}},
		{name: "I_f", fallback: []int{1, 2}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			prototype, err := apvssBuildPrototype(
				&fixture.context,
				fixture.leaf,
				fixture.receiverSecrets,
				fixture.signingSecrets,
				&fixture.witness,
				profile.fallback,
			)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := apvssDecodeLeafPrototype(wire, &fixture.context)
			if err != nil {
				t.Fatalf("decode APVSS leaf: %v", err)
			}
			encodedAgain, err := apvssLeafPrototypeCanonicalBytes(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encodedAgain, wire) {
				t.Fatal("APVSS leaf codec changed canonical bytes")
			}
			wantDigest := hashBytes([]byte(apvssLeafDigestDomain), wire)
			if !bytes.Equal(decoded.digest, wantDigest) || !bytes.Equal(prototype.digest, wantDigest) {
				t.Fatal("APVSS leaf digest did not bind canonical wire")
			}
		})
	}
}

func TestAPVSSLeafPrototypeCodecRejectsUnknownFallbackProfileV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	prototype, err := apvssBuildPrototype(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		fixture.signingSecrets,
		&fixture.witness,
		[]int{1},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		t.Fatal(err)
	}
	offset := bytes.Index(wire, []byte(apvssFallbackExactLaneProfile))
	if offset < 0 {
		t.Fatal("explicit fallback profile is absent from canonical wire")
	}
	unknown := []byte("unknown-xx")
	if len(unknown) != len(apvssFallbackExactLaneProfile) {
		t.Fatal("test unknown profile must preserve canonical field length")
	}
	bad := append([]byte(nil), wire...)
	copy(bad[offset:offset+len(unknown)], unknown)
	if _, err := apvssDecodeLeafPrototype(bad, &fixture.context); err == nil {
		t.Fatal("decoded APVSS leaf with an unknown fallback profile")
	}
}

func TestAPVSSLeafPrototypeCodecRejectsMutationV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	prototype, err := apvssBuildPrototype(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		fixture.signingSecrets,
		&fixture.witness,
		[]int{1},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), wire...), 0)
		if _, err := apvssDecodeLeafPrototype(bad, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with trailing bytes")
		}
	})
	t.Run("signature response", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(prototype)
		one := cvTestScalar(1)
		bad.acks[0].signature.z.Add(&bad.acks[0].signature.z, &one)
		badWire, err := apvssLeafPrototypeCanonicalBytes(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototype(badWire, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with a mutated ACK response")
		}
	})
	t.Run("wrong context", func(t *testing.T) {
		other := cvCloneLeafContext(fixture.context)
		other.epoch++
		if _, err := apvssDecodeLeafPrototype(wire, &other); err == nil {
			t.Fatal("accepted APVSS leaf in another epoch")
		}
	})
	t.Run("fallback response", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(prototype)
		proxy := &cvLeaf{proof: bad.fallbackProofs[0].proof}
		bad.fallbackProofs[0].proof = cvCloneLeafForTest(proxy).proof
		one := cvTestScalar(1)
		bad.fallbackProofs[0].proof.sharing.zScalar.Add(
			&bad.fallbackProofs[0].proof.sharing.zScalar,
			&one,
		)
		badWire, err := apvssLeafPrototypeCanonicalBytes(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototype(badWire, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with a mutated fallback proof")
		}
	})
}

func TestAPVSSLaneACKMessageCodecV1(t *testing.T) {
	fixture := apvssFixture(t, 4, 1)
	ack, err := apvssIssueLaneACK(
		&fixture.context,
		fixture.leaf,
		1,
		fixture.receiverSecrets[0],
		fixture.signingSecrets[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	message := &apvssLaneACKMessage{
		dealerID:   fixture.leaf.dealerID,
		leafDigest: append([]byte(nil), fixture.leaf.digest...),
		ack:        ack,
	}
	wire, err := apvssLaneACKMessageCanonicalBytes(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := apvssDecodeLaneACKMessage(wire, fixture.leaf)
	if err != nil {
		t.Fatalf("decode ACK message: %v", err)
	}
	encodedAgain, err := apvssLaneACKMessageCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(encodedAgain, wire) {
		t.Fatal("ACK message codec changed canonical bytes")
	}

	badLeaf := cvCloneLeafForTest(fixture.leaf)
	badLeaf.dealerID++
	badLeaf.digest = cvLeafDigest(badLeaf)
	if _, err := apvssDecodeLaneACKMessage(wire, badLeaf); err == nil {
		t.Fatal("ACK message replayed for another dealer leaf")
	}
}

func TestAPVSSLaneOfferProjectionPreservesStatementV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	const receiverIndex = 4
	offer, err := apvssLaneOfferFromLeaf(fixture.leaf, receiverIndex)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := apvssLaneOfferCanonicalBytes(offer, &fixture.context)
	if err != nil {
		t.Fatal(err)
	}
	fullWire, err := cvLeafCanonicalBytes(fixture.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) >= len(fullWire) {
		t.Fatalf("lane projection bytes = %d, full leaf = %d", len(wire), len(fullWire))
	}
	decoded, err := apvssDecodeLaneOffer(wire, &fixture.context, receiverIndex)
	if err != nil {
		t.Fatalf("decode lane offer: %v", err)
	}
	view, err := apvssLaneOfferLeafView(&fixture.context, decoded)
	if err != nil {
		t.Fatal(err)
	}
	fullStatement, err := apvssLaneStatementBytes(fixture.leaf, receiverIndex)
	if err != nil {
		t.Fatal(err)
	}
	projectedStatement, err := apvssLaneStatementBytes(view, receiverIndex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fullStatement, projectedStatement) {
		t.Fatal("lane projection changed the signed statement")
	}
	ack, err := apvssIssueVerifiedLaneACK(
		&fixture.context, view, receiverIndex,
		fixture.receiverSecrets[receiverIndex-1], fixture.signingSecrets[receiverIndex-1],
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyLaneACK(fixture.leaf, &ack); err != nil {
		t.Fatalf("full leaf rejected projection-issued ACK: %v", err)
	}
	reencoded, err := apvssLaneOfferCanonicalBytes(decoded, &fixture.context)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatal("lane offer codec changed canonical bytes")
	}
	if _, err := apvssDecodeLaneOffer(append(append([]byte(nil), wire...), 0), &fixture.context, receiverIndex); err == nil {
		t.Fatal("accepted trailing lane offer bytes")
	}
	var legacy bytes.Buffer
	_, _ = legacy.Write(wire)
	cvWriteCiphertext(&legacy, &offer.receiver.encryptedShare.blinding)
	if _, err := apvssDecodeLaneOffer(legacy.Bytes(), &fixture.context, receiverIndex); err == nil {
		t.Fatal("accepted a structural v1 lane offer carrying the legacy blinding ciphertext")
	}
	if _, err := apvssDecodeLaneOffer(wire, &fixture.context, receiverIndex-1); err == nil {
		t.Fatal("accepted lane offer for another receiver")
	}
}
