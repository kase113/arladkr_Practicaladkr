package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const apvssMaxLeafWireBytes = cvMaxLeafWireBytes

func apvssHasLeafWireDomain(wire []byte) bool {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssLeafWireDomain))
	return err == nil && bytes.Equal(domain, []byte(apvssLeafWireDomain))
}

func apvssLaneOfferCanonicalBytes(offer *apvssLaneOffer, context *cvLeafContext) ([]byte, error) {
	if context == nil || context.proofProfile != cvLeafStructuralProofProfile {
		return nil, fmt.Errorf("APVSS lane offers require the structural proof profile")
	}
	leaf, err := apvssLaneOfferLeafView(context, offer)
	if err != nil {
		return nil, err
	}
	if _, err := apvssLaneStatementBytes(leaf, offer.receiverIndex); err != nil {
		return nil, err
	}
	contextDigest := cvLeafContextDigest(context)
	if len(contextDigest) != 32 {
		return nil, fmt.Errorf("invalid APVSS lane offer context")
	}
	return apvssLaneOfferCanonicalBytesTrusted(offer, contextDigest)
}

// The caller must already have validated the structural leaf and context.
func apvssLaneOfferCanonicalBytesTrusted(offer *apvssLaneOffer, contextDigest []byte) ([]byte, error) {
	if offer == nil || len(contextDigest) != 32 || len(offer.leafDigest) != 32 ||
		offer.receiverIndex <= 0 || offer.receiver.receiverIndex != offer.receiverIndex ||
		offer.receiver.encryptedShare == nil {
		return nil, fmt.Errorf("invalid trusted APVSS lane offer")
	}
	lane := &offer.receiver
	share := lane.encryptedShare
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssLaneOfferDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, contextDigest); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, offer.dealerID)
	if err := cvWriteBytes(&wire, offer.leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, offer.receiverIndex); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(offer.coefficientCommitments)); err != nil {
		return nil, err
	}
	for i := range offer.coefficientCommitments {
		cvWritePoint(&wire, &offer.coefficientCommitments[i])
	}
	cvWritePoint(&wire, &lane.receiverPublicKey)
	cvWritePoint(&wire, &share.commitment)
	if err := cvWriteUint32(&wire, len(share.scalarChunks)); err != nil {
		return nil, err
	}
	for i := range share.scalarChunks {
		cvWriteCiphertext(&wire, &share.scalarChunks[i])
	}
	if wire.Len() > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("APVSS lane offer exceeds the wire safety limit")
	}
	return wire.Bytes(), nil
}

func apvssDecodeLaneOffer(
	wire []byte,
	expectedContext *cvLeafContext,
	expectedReceiverIndex int,
) (*apvssLaneOffer, error) {
	if expectedContext == nil || expectedContext.proofProfile != cvLeafStructuralProofProfile || expectedReceiverIndex <= 0 ||
		expectedReceiverIndex > len(expectedContext.receiverPublicKeys) || len(wire) == 0 ||
		len(wire) > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("invalid expected APVSS lane offer context or wire")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssLaneOfferDomain))
	if err != nil || !bytes.Equal(domain, []byte(apvssLaneOfferDomain)) {
		return nil, fmt.Errorf("invalid APVSS lane offer domain")
	}
	expectedContextDigest := cvLeafContextDigest(expectedContext)
	contextDigest, err := r.bytes(32)
	if err != nil || !bytes.Equal(contextDigest, expectedContextDigest) {
		return nil, fmt.Errorf("APVSS lane offer context mismatch")
	}
	offer := &apvssLaneOffer{}
	offer.dealerID, err = r.uint64()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS lane offer dealer: %w", err)
	}
	offer.leafDigest, err = r.bytes(32)
	if err != nil || len(offer.leafDigest) != 32 {
		return nil, fmt.Errorf("invalid APVSS lane offer leaf digest")
	}
	offer.receiverIndex, err = r.uint32()
	if err != nil || offer.receiverIndex != expectedReceiverIndex {
		return nil, fmt.Errorf("APVSS lane offer receiver mismatch")
	}
	coefficientCount := expectedContext.sharingDegree + 1
	if err := cvReadExactCount(r, coefficientCount, "APVSS lane offer commitments"); err != nil {
		return nil, err
	}
	offer.coefficientCommitments = make([]bls12381.G1Affine, coefficientCount)
	for i := range offer.coefficientCommitments {
		offer.coefficientCommitments[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS lane offer commitment %d: %w", i, err)
		}
	}
	offer.receiver.receiverIndex = offer.receiverIndex
	offer.receiver.receiverPublicKey, err = r.point()
	if err != nil || !offer.receiver.receiverPublicKey.Equal(
		&expectedContext.receiverPublicKeys[offer.receiverIndex-1],
	) {
		return nil, fmt.Errorf("APVSS lane offer receiver key mismatch")
	}
	share := &cvEncryptedShare{receiverPublicKey: offer.receiver.receiverPublicKey}
	share.commitment, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS lane offer commitment: %w", err)
	}
	chunks, err := cvChunkCount(expectedContext.profile)
	if err != nil {
		return nil, err
	}
	if err := cvReadExactCount(r, chunks, "APVSS lane offer scalar chunks"); err != nil {
		return nil, err
	}
	if err := cvRequireRemaining(r, chunks, 2*bls12381.SizeOfG1AffineCompressed, "APVSS lane offer ciphertexts"); err != nil {
		return nil, err
	}
	share.scalarChunks = make([]cvElGamalCiphertext, chunks)
	for i := range share.scalarChunks {
		share.scalarChunks[i], err = r.ciphertext()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS lane offer ciphertext %d: %w", i, err)
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS lane offer framing")
	}
	offer.receiver.encryptedShare = share
	leaf, err := apvssLaneOfferLeafView(expectedContext, offer)
	if err != nil {
		return nil, err
	}
	if _, err := apvssLaneStatementBytes(leaf, offer.receiverIndex); err != nil {
		return nil, err
	}
	canonical, err := apvssLaneOfferCanonicalBytesTrusted(offer, expectedContextDigest)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS lane offer")
	}
	return offer, nil
}

func apvssValidatePartitionShape(prototype *apvssLeafPrototype) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	n := len(prototype.leaf.receivers)
	if err := apvssRequireFallbackBackend(prototype.fallbackProfile); err != nil {
		return err
	}
	fallbackIndices, err := apvssPrototypeFallbackIndices(prototype)
	if err != nil {
		return err
	}
	if len(fallbackIndices) > prototype.leaf.context.sharingDegree ||
		len(prototype.acks)+len(fallbackIndices) != n {
		return fmt.Errorf("APVSS ACK and fallback sets do not cover receivers exactly")
	}
	covered := make([]bool, n)
	previous := 0
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		if ack.receiverIndex <= previous || ack.receiverIndex <= 0 || ack.receiverIndex > n ||
			covered[ack.receiverIndex-1] || !cvValidG1(&ack.signature.r, false) {
			return fmt.Errorf("APVSS ACK indices or signature points are not canonical")
		}
		covered[ack.receiverIndex-1] = true
		previous = ack.receiverIndex
	}
	previous = 0
	for i, receiverIndex := range fallbackIndices {
		if receiverIndex <= previous || receiverIndex <= 0 || receiverIndex > n ||
			covered[receiverIndex-1] {
			return fmt.Errorf("APVSS fallback indices are not the ACK complement")
		}
		if apvssNormalizeFallbackProfile(prototype.fallbackProfile) == apvssFallbackExactLaneProfile &&
			prototype.fallbackProofs[i].proof == nil {
			return fmt.Errorf("missing exact APVSS fallback proof")
		}
		covered[receiverIndex-1] = true
		previous = receiverIndex
	}
	for receiver, ok := range covered {
		if !ok {
			return fmt.Errorf("APVSS receiver %d is absent from ACK and fallback sets", receiver+1)
		}
	}
	return nil
}

func apvssLeafPrototypeCanonicalBytes(prototype *apvssLeafPrototype) ([]byte, error) {
	if prototype == nil || prototype.leaf == nil {
		return nil, fmt.Errorf("invalid APVSS prototype leaf")
	}
	if err := apvssValidatePartitionShape(prototype); err != nil {
		return nil, err
	}
	leafWire, err := cvLeafCanonicalBytes(prototype.leaf)
	if err != nil {
		return nil, err
	}

	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssLeafWireDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, leafWire); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(prototype.acks)); err != nil {
		return nil, err
	}
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		if err := cvWriteUint32(&wire, ack.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &ack.signature.r)
		cvWriteScalar(&wire, &ack.signature.z)
	}
	if err := cvWriteUint32(&wire, apvssFallbackProfileMarker); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, []byte(prototype.fallbackProfile)); err != nil {
		return nil, err
	}
	fallbackIndices, err := apvssPrototypeFallbackIndices(prototype)
	if err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(fallbackIndices)); err != nil {
		return nil, err
	}
	if apvssNormalizeFallbackProfile(prototype.fallbackProfile) != apvssFallbackExactLaneProfile {
		for _, receiverIndex := range fallbackIndices {
			if err := cvWriteUint32(&wire, receiverIndex); err != nil {
				return nil, err
			}
		}
		var proofWire []byte
		if prototype.compactFallback != nil {
			proofWire, err = apvssBatchFallbackProofCanonicalBytes(
				prototype.leaf, prototype.compactFallback, prototype.fallbackProfile,
			)
			if err != nil {
				return nil, err
			}
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	} else {
		for i := range prototype.fallbackProofs {
			fallback := &prototype.fallbackProofs[i]
			if err := cvWriteUint32(&wire, fallback.receiverIndex); err != nil {
				return nil, err
			}
			proofWire, err := cvLeafProofCanonicalBytes(fallback.proof)
			if err != nil {
				return nil, err
			}
			if err := cvWriteBytes(&wire, proofWire); err != nil {
				return nil, err
			}
		}
	}
	if wire.Len() > apvssMaxLeafWireBytes {
		return nil, fmt.Errorf("APVSS leaf exceeds the wire safety limit")
	}
	return wire.Bytes(), nil
}

func apvssDecodeLeafPrototype(
	wire []byte,
	expectedContext *cvLeafContext,
) (*apvssLeafPrototype, error) {
	if expectedContext == nil || expectedContext.proofProfile != cvLeafStructuralProofProfile ||
		len(wire) == 0 || len(wire) > apvssMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid expected APVSS leaf context or wire")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssLeafWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(apvssLeafWireDomain)) {
		return nil, fmt.Errorf("invalid APVSS leaf wire domain")
	}
	baseWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil || len(baseWire) == 0 {
		return nil, fmt.Errorf("invalid APVSS structural leaf field")
	}
	leaf, err := cvDecodeLeaf(baseWire, expectedContext)
	if err != nil {
		return nil, err
	}
	n := len(leaf.receivers)
	ackCount, err := r.uint32()
	if err != nil || ackCount < 0 || ackCount > n {
		return nil, fmt.Errorf("invalid APVSS ACK count")
	}
	prototype := &apvssLeafPrototype{leaf: leaf, acks: make([]apvssLaneACK, ackCount)}
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		ack.receiverIndex, err = r.uint32()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK receiver index: %w", err)
		}
		ack.signature.r, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK nonce: %w", err)
		}
		ack.signature.z, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK response: %w", err)
		}
	}
	profileMarkerOrCount, err := r.uint32()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS fallback profile/count: %w", err)
	}
	if profileMarkerOrCount != apvssFallbackProfileMarker {
		return nil, fmt.Errorf("missing APVSS fallback proof profile marker")
	}
	profileWire, err := r.bytes(128)
	if err != nil {
		return nil, fmt.Errorf("decode APVSS fallback proof profile: %w", err)
	}
	prototype.fallbackProfile = string(profileWire)
	if err := apvssRequireFallbackBackend(prototype.fallbackProfile); err != nil {
		return nil, err
	}
	fallbackCount, err := r.uint32()
	if err != nil || fallbackCount < 0 || fallbackCount > expectedContext.sharingDegree {
		return nil, fmt.Errorf("invalid APVSS fallback proof count")
	}
	if apvssNormalizeFallbackProfile(prototype.fallbackProfile) != apvssFallbackExactLaneProfile {
		prototype.fallbackIndices = make([]int, fallbackCount)
		for i := range prototype.fallbackIndices {
			prototype.fallbackIndices[i], err = r.uint32()
			if err != nil {
				return nil, fmt.Errorf("decode compact APVSS fallback receiver index: %w", err)
			}
		}
		proofWire, readErr := r.bytes(cvMaxLeafWireBytes)
		if readErr != nil {
			return nil, fmt.Errorf("decode compact APVSS fallback proof: %w", readErr)
		}
		if fallbackCount == 0 {
			if len(proofWire) != 0 {
				return nil, fmt.Errorf("empty compact APVSS fallback set carries proof bytes")
			}
		} else {
			// Partition verification below checks the proof exactly once after the
			// outer ordered I set has also been decoded and matched.
			switch apvssNormalizeFallbackProfile(prototype.fallbackProfile) {
			case apvssFallbackCompactBatchProfile:
				prototype.compactFallback, err = apvssDecodeCompactFallbackProofWithVerify(
					proofWire, leaf, false,
				)
			case apvssFallbackFeldmanBatchProfile:
				prototype.compactFallback, err = apvssDecodeFeldmanFallbackProofWithVerify(
					proofWire, leaf, false,
				)
			}
			if err != nil {
				return nil, err
			}
		}
	} else {
		prototype.fallbackProofs = make([]apvssFallbackProof, fallbackCount)
		for i := range prototype.fallbackProofs {
			fallback := &prototype.fallbackProofs[i]
			fallback.receiverIndex, err = r.uint32()
			if err != nil {
				return nil, fmt.Errorf("decode APVSS fallback receiver index: %w", err)
			}
			fallbackContext, _, deriveErr := apvssFallbackLeaf(leaf, fallback.receiverIndex)
			if deriveErr != nil {
				return nil, deriveErr
			}
			proofSize, sizeErr := cvLeafProofWireSize(fallbackContext)
			if sizeErr != nil {
				return nil, sizeErr
			}
			proofWire, readErr := cvReadExactBytes(r, proofSize, "APVSS fallback proof")
			if readErr != nil {
				return nil, readErr
			}
			fallback.proof, err = cvDecodeLeafProof(proofWire, fallbackContext)
			if err != nil {
				return nil, err
			}
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing APVSS leaf bytes")
	}
	if err := apvssValidatePartitionShape(prototype); err != nil {
		return nil, err
	}
	canonical, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS leaf encoding")
	}
	// cvDecodeLeaf already performed the complete structural-leaf check.
	// Verify only the APVSS authentication partition here so an untrusted wire
	// is checked once, rather than repeating all commitment evaluations.
	if err := apvssVerifyPrototypePartition(prototype); err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssLaneACKMessageCanonicalBytes(message *apvssLaneACKMessage) ([]byte, error) {
	if message == nil || len(message.leafDigest) != 32 || message.ack.receiverIndex <= 0 ||
		!cvValidG1(&message.ack.signature.r, false) {
		return nil, fmt.Errorf("invalid APVSS ACK message")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssACKMessageDomain)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, message.dealerID)
	if err := cvWriteBytes(&wire, message.leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, message.ack.receiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &message.ack.signature.r)
	cvWriteScalar(&wire, &message.ack.signature.z)
	return wire.Bytes(), nil
}

func apvssDecodeLaneACKMessage(
	wire []byte,
	leaf *cvLeaf,
) (*apvssLaneACKMessage, error) {
	if leaf == nil || len(leaf.digest) != 32 {
		return nil, fmt.Errorf("invalid APVSS ACK message leaf")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssACKMessageDomain))
	if err != nil || !bytes.Equal(domain, []byte(apvssACKMessageDomain)) {
		return nil, fmt.Errorf("invalid APVSS ACK message domain")
	}
	message := &apvssLaneACKMessage{}
	message.dealerID, err = r.uint64()
	if err != nil || message.dealerID != leaf.dealerID {
		return nil, fmt.Errorf("APVSS ACK message dealer mismatch")
	}
	message.leafDigest, err = r.bytes(32)
	if err != nil || !bytes.Equal(message.leafDigest, leaf.digest) {
		return nil, fmt.Errorf("APVSS ACK message leaf digest mismatch")
	}
	message.ack.receiverIndex, err = r.uint32()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS ACK message receiver index: %w", err)
	}
	message.ack.signature.r, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS ACK message nonce: %w", err)
	}
	message.ack.signature.z, err = r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS ACK message response or framing")
	}
	canonical, err := apvssLaneACKMessageCanonicalBytes(message)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS ACK message")
	}
	if err := apvssVerifyLaneACK(leaf, &message.ack); err != nil {
		return nil, err
	}
	return message, nil
}
