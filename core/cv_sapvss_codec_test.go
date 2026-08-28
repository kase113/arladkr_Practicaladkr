package core

import (
	"bytes"
	"encoding/binary"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVLeafCodecRoundTripAndRejectsTrailingBytes(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 8, maxComponents: 1}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	receiverSecret := cvTestScalar(13)
	receiverKey, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		t.Fatal(err)
	}
	context := cvLeafContext{
		sessionID:                 []byte("codec-leaf-session"),
		epoch:                     23,
		sharingDegree:             0,
		profile:                   profile,
		receiverPublicKeys:        []bls12381.G1Affine{receiverKey},
		receiverSigningPublicKeys: cvTestSigningKeys(t, 1, 27001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	leaf, err := cvReferenceDeal(
		context,
		41,
		[]fr.Element{cvTestScalar(5)},
		[]fr.Element{cvTestScalar(7)},
		[][]fr.Element{cvTestCoins(chunks, 101)},
		[]fr.Element{cvTestScalar(401)},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	proofWire, err := cvLeafProofCanonicalBytes(leaf.proof)
	if err != nil {
		t.Fatal(err)
	}
	proofSize, err := cvLeafProofWireSize(&context)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofWire) != proofSize {
		t.Fatalf("Leaf proof wire size = %d, want %d", len(proofWire), proofSize)
	}
	leafSize, err := cvLeafWireSize(&context)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != leafSize {
		t.Fatalf("Leaf wire size = %d, want %d", len(wire), leafSize)
	}

	decoded, err := cvDecodeLeaf(wire, &context)
	if err != nil {
		t.Fatalf("decode canonical leaf: %v", err)
	}
	decodedWire, err := cvLeafCanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(decoded.digest, leaf.digest) {
		t.Fatal("decoded Leaf did not preserve its canonical wire or digest")
	}

	trailing := append(append([]byte(nil), wire...), 0)
	if _, err := cvDecodeLeaf(trailing, &context); err == nil {
		t.Fatal("accepted trailing Leaf bytes")
	}

	if _, err := cvDecodeLeafProof(proofWire, &context); err != nil {
		t.Fatalf("decode canonical Leaf proof: %v", err)
	}
	firstVectorCountOffset := 6*bls12381.SizeOfG1AffineCompressed + 4*fr.Bytes
	for _, test := range []struct {
		name  string
		count uint32
	}{
		{name: "undersized vector", count: cvChunkProofRepetitions - 1},
		{name: "oversized vector", count: cvChunkProofRepetitions + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := append([]byte(nil), proofWire...)
			binary.BigEndian.PutUint32(bad[firstVectorCountOffset:firstVectorCountOffset+4], test.count)
			if _, err := cvDecodeLeafProof(bad, &context); err == nil {
				t.Fatalf("accepted Leaf proof with vector count %d", test.count)
			}
		})
	}
	t.Run("proof trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), proofWire...), 0)
		if _, err := cvDecodeLeafProof(bad, &context); err == nil {
			t.Fatal("accepted trailing Leaf proof bytes")
		}
	})
	t.Run("noncanonical scalar", func(t *testing.T) {
		bad := append([]byte(nil), proofWire...)
		firstScalarOffset := 6 * bls12381.SizeOfG1AffineCompressed
		copy(bad[firstScalarOffset:firstScalarOffset+fr.Bytes], fr.Modulus().FillBytes(make([]byte, fr.Bytes)))
		if _, err := cvDecodeLeafProof(bad, &context); err == nil {
			t.Fatal("accepted noncanonical Leaf proof scalar")
		}
	})
	t.Run("noncanonical point", func(t *testing.T) {
		bad := append([]byte(nil), proofWire...)
		bad[0] &^= 0x80
		if _, err := cvDecodeLeafProof(bad, &context); err == nil {
			t.Fatal("accepted noncanonical Leaf proof point")
		}
	})
}

func TestCVLeafCodecSizesAllowLargeValidContext(t *testing.T) {
	const receiverCount = 256
	keys := make([]bls12381.G1Affine, receiverCount)
	for i := range keys {
		var err error
		keys[i], err = cvReceiverPublicKey(cvTestScalar(uint64(i + 1)))
		if err != nil {
			t.Fatal(err)
		}
	}
	context := cvLeafContext{
		sessionID:                 []byte("codec-large-leaf-session"),
		epoch:                     24,
		sharingDegree:             85,
		profile:                   cvChunkProfile{chunkBits: 8, maxComponents: 86},
		receiverPublicKeys:        keys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(keys), 28001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	if err := cvValidateLeafContext(&context); err != nil {
		t.Fatalf("large context is not valid: %v", err)
	}
	proofSize, err := cvLeafProofWireSize(&context)
	if err != nil {
		t.Fatal(err)
	}
	leafSize, err := cvLeafWireSize(&context)
	if err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{"proof": proofSize, "leaf": leafSize} {
		if size <= cvMaxCanonicalFieldBytes {
			t.Fatalf("large %s size = %d, want greater than legacy 16 MiB cap", name, size)
		}
		if size > 64<<20 {
			t.Fatalf("large %s size = %d, exceeds independent 64 MiB safety cap", name, size)
		}
	}
}

func TestCVLeafCodecRoundTripWithMultipleReceiversAndDegree(t *testing.T) {
	context, _, leaves := cvM2Fixture(t)
	wire, err := cvLeafCanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLeaf(wire, &context)
	if err != nil {
		t.Fatalf("decode multi-receiver degree-%d Leaf: %v", context.sharingDegree, err)
	}
	decodedWire, err := cvLeafCanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) {
		t.Fatal("multi-receiver Leaf roundtrip changed canonical wire")
	}
}

func TestCVStructuralV2WireRejectsLegacyBlindingFields(t *testing.T) {
	fixture := apvssFixture(t, 1, 0)

	t.Run("legacy profile", func(t *testing.T) {
		legacy := cvCloneLeafContext(fixture.context)
		legacy.proofProfile = "m1a-structural-no-nizk"
		if err := cvValidateLeafContext(&legacy); err == nil {
			t.Fatal("accepted the legacy structural proof profile")
		}
	})

	t.Run("leaf", func(t *testing.T) {
		wire, err := cvLeafCanonicalBytes(fixture.leaf)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) == 0 || wire[len(wire)-1] != 0 {
			t.Fatal("unexpected structural leaf capability framing")
		}
		var legacy bytes.Buffer
		_, _ = legacy.Write(wire[:len(wire)-1])
		cvWriteCiphertext(&legacy, &fixture.leaf.receivers[0].encryptedShare.blinding)
		_ = legacy.WriteByte(wire[len(wire)-1])
		if legacy.Len()-len(wire) != 2*bls12381.SizeOfG1AffineCompressed {
			t.Fatal("legacy leaf fixture did not add exactly one blinding ciphertext")
		}
		if _, err := cvDecodeLeaf(legacy.Bytes(), &fixture.context); err == nil {
			t.Fatal("accepted a structural v1 leaf carrying the legacy blinding ciphertext")
		}
	})

	t.Run("aggregate", func(t *testing.T) {
		agg, err := cvAgg(&fixture.context, []*cvLeaf{fixture.leaf})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := cvAggregateCanonicalBytes(agg)
		if err != nil {
			t.Fatal(err)
		}
		var legacy bytes.Buffer
		_, _ = legacy.Write(wire)
		cvWriteCiphertext(&legacy, &agg.receivers[0].blinding)
		if _, err := cvDecodeAggregate(legacy.Bytes()); err == nil {
			t.Fatal("accepted a structural v1 aggregate carrying the legacy blinding ciphertext")
		}
	})
}

func TestCVReceiptCodecRoundTripAndRejectsTampering(t *testing.T) {
	context, secrets, leaves := cvM2Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := cvDecShare(agg, secrets[0], 1)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := cvDecodeReceipt(wire, &context, agg, 1)
	if err != nil {
		t.Fatalf("decode canonical receipt: %v", err)
	}
	decodedWire, err := cvReceiptCanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(decoded.digest, receipt.digest) {
		t.Fatal("decoded receipt did not preserve its canonical wire or digest")
	}

	t.Run("aggregate binding", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		aggregateOffset := 4 + len(cvReceiptDomain) + 4
		bad[aggregateOffset] ^= 1
		if _, err := cvDecodeReceipt(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted receipt bound to another aggregate")
		}
	})
	t.Run("receiver binding", func(t *testing.T) {
		if _, err := cvDecodeReceipt(wire, &context, agg, 2); err == nil {
			t.Fatal("accepted receipt under another receiver index")
		}
	})
	t.Run("proof mutation", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		bad[len(bad)-1] ^= 1
		if _, err := cvDecodeReceipt(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted receipt with a mutated DLEQ response")
		}
	})
	t.Run("receipt mode", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		modeOffset := 4 + len(cvReceiptDomain) + 4 + 32 + 4
		bad[modeOffset+3] = 0
		if _, err := cvDecodeReceipt(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted a Pedersen receipt mode for a Feldman aggregate")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), wire...), 0)
		if _, err := cvDecodeReceipt(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted trailing receipt bytes")
		}
	})
}
