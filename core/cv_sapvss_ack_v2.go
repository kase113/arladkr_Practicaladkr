package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLaneOfferWireDomainV2      = "ARL-CV-sAPVSS/v2-scalar-group/lane-offer"
	cvFallbackLaneWireDomainV2   = "ARL-CV-sAPVSS/v2-scalar-group/fallback-lane"
	cvOwnershipProofWireDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/ownership-proof"
	cvACKWireDomainV2            = "ARL-CV-sAPVSS/v2-scalar-group/ack"
	cvACKStatementDomainV2       = "ARL-CV-sAPVSS/v2-scalar-group/ack-statement"
	cvCiphertextDigestDomainV2   = "ARL-CV-sAPVSS/v2-scalar-group/ciphertexts"
)

type cvACKEvidenceV2 struct {
	Ownership cvOwnershipProofV2
	Signature []byte
}

func cvFallbackLaneOfferV2CanonicalBytes(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback lane")
	}
	return cvFallbackLaneOfferV2CanonicalBytesAfterValidation(context, dealerID, offer)
}

func cvFallbackLaneOfferV2CanonicalBytesAfterValidation(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	if context == nil || dealerID < 0 || offer == nil || offer.ReceiverID < 0 || offer.ReceiverIndex <= 0 {
		return nil, fmt.Errorf("invalid verified CV V2 fallback lane")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || len(offer.ScalarChunks) != chunks {
		return nil, fmt.Errorf("invalid verified CV V2 fallback lane dimensions")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackLaneWireDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	if err := cvWriteUint32(&wire, offer.ReceiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &offer.Evaluation)
	if err := cvWriteUint32(&wire, len(offer.ScalarChunks)); err != nil {
		return nil, err
	}
	for chunk := range offer.ScalarChunks {
		cvWriteCiphertext(&wire, &offer.ScalarChunks[chunk])
	}
	cvWriteCiphertext(&wire, &offer.Blinding)
	return wire.Bytes(), nil
}

func cvDecodeFallbackLaneOfferV2(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackLaneWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackLaneWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane domain")
	}
	contextDigest, err := r.bytes(32)
	wantContext, contextErr := cvLeafContextDigestV2(context)
	if err != nil || contextErr != nil || !bytes.Equal(contextDigest, wantContext) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer != uint64(expectedDealer) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane dealer")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID != uint64(expectedReceiverID) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane receiver")
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex != expectedReceiverIndex {
		return nil, fmt.Errorf("invalid CV V2 fallback lane receiver index")
	}
	evaluation, err := r.point()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback lane evaluation")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != chunks {
		return nil, fmt.Errorf("invalid CV V2 fallback scalar chunk count")
	}
	offer := &cvReceiverLaneOfferV2{
		ReceiverID: expectedReceiverID, ReceiverIndex: expectedReceiverIndex, Evaluation: evaluation,
		ScalarChunks: make([]cvElGamalCiphertext, chunks),
	}
	for chunk := 0; chunk < chunks; chunk++ {
		offer.ScalarChunks[chunk], err = r.ciphertext()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 fallback scalar ciphertext")
		}
	}
	offer.Blinding, err = r.ciphertext()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback blinding ciphertext")
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 fallback lane bytes")
	}
	canonical, err := cvFallbackLaneOfferV2CanonicalBytesAfterValidation(context, expectedDealer, offer)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback lane")
	}
	return offer, nil
}

func cvVerifyDecryptAndSignACKV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey,
) (*cvACKEvidenceV2, fr.Element, bls12381.G1Affine, error) {
	return cvVerifyDecryptAndSignACKModeV2(
		context, dealerID, offer, receiverPublicKey, receiverSecret,
		identityPublicKey, identitySecret, true,
	)
}

func cvVerifyDecryptAndSignACKAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey,
) (*cvACKEvidenceV2, fr.Element, bls12381.G1Affine, error) {
	return cvVerifyDecryptAndSignACKModeV2(
		context, dealerID, offer, receiverPublicKey, receiverSecret,
		identityPublicKey, identitySecret, false,
	)
}

func cvVerifyDecryptAndSignACKModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey, validatePoints bool,
) (*cvACKEvidenceV2, fr.Element, bls12381.G1Affine, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize || len(identitySecret) != ed25519.PrivateKeySize ||
		!bytes.Equal(identitySecret.Public().(ed25519.PublicKey), identityPublicKey) {
		return nil, fr.Element{}, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 receiver identity secret")
	}
	var scalar fr.Element
	var blinding bls12381.G1Affine
	var err error
	if validatePoints {
		scalar, blinding, err = cvVerifyAndDecryptReceiverLanesV2(
			context, dealerID, offer, receiverPublicKey, receiverSecret,
		)
	} else {
		scalar, blinding, err = cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
			context, dealerID, offer, receiverPublicKey, receiverSecret,
		)
	}
	if err != nil {
		return nil, fr.Element{}, bls12381.G1Affine{}, err
	}
	statement, err := cvACKStatementAfterValidationV2(context, dealerID, offer)
	if err != nil {
		return nil, fr.Element{}, bls12381.G1Affine{}, err
	}
	evidence := &cvACKEvidenceV2{
		Ownership: cvCloneOwnershipProofV2(&offer.Ownership),
		Signature: ed25519.Sign(identitySecret, statement),
	}
	return evidence, scalar, blinding, nil
}

func cvVerifyACKV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceV2,
) error {
	return cvVerifyACKModeV2(context, dealerID, offer, receiverPublicKey, identityPublicKey, evidence, true)
}

func cvVerifyACKAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceV2,
) error {
	return cvVerifyACKModeV2(context, dealerID, offer, receiverPublicKey, identityPublicKey, evidence, false)
}

func cvVerifyACKAfterLocalOwnershipValidationV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	identityPublicKey ed25519.PublicKey, evidence *cvACKEvidenceV2,
) error {
	if offer == nil || evidence == nil || len(identityPublicKey) != ed25519.PublicKeySize ||
		len(evidence.Signature) != ed25519.SignatureSize ||
		!cvEqualOwnershipProofV2(&offer.Ownership, &evidence.Ownership) {
		return fmt.Errorf("invalid verified CV V2 ACK evidence")
	}
	statement, err := cvACKStatementAfterValidationV2(context, dealerID, offer)
	if err != nil || !ed25519.Verify(identityPublicKey, statement, evidence.Signature) {
		return fmt.Errorf("invalid CV V2 ACK signature")
	}
	return nil
}

func cvVerifyACKModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceV2, validatePoints bool,
) error {
	if offer == nil || evidence == nil || len(identityPublicKey) != ed25519.PublicKeySize ||
		len(evidence.Signature) != ed25519.SignatureSize ||
		!cvEqualOwnershipProofV2(&offer.Ownership, &evidence.Ownership) {
		return fmt.Errorf("invalid CV V2 ACK evidence")
	}
	var ownershipErr error
	if validatePoints {
		ownershipErr = cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey)
	} else {
		ownershipErr = cvVerifyOwnershipAfterPointDecodingV2(context, dealerID, offer, receiverPublicKey)
	}
	if ownershipErr != nil {
		return ownershipErr
	}
	statement, err := cvACKStatementAfterValidationV2(context, dealerID, offer)
	if err != nil || !ed25519.Verify(identityPublicKey, statement, evidence.Signature) {
		return fmt.Errorf("invalid CV V2 ACK signature")
	}
	return nil
}

func cvACKStatementV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	return cvACKStatementModeV2(context, dealerID, offer, true)
}

func cvACKStatementAfterValidationV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	return cvACKStatementModeV2(context, dealerID, offer, false)
}

func cvACKStatementModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2, validatePoints bool,
) ([]byte, error) {
	if dealerID < 0 || context == nil || offer == nil || len(context.ReceiverRegistryDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 ACK statement")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	var ciphertextDigest []byte
	if validatePoints {
		ciphertextDigest, err = cvCiphertextDigestV2(context, offer)
	} else {
		ciphertextDigest, err = cvCiphertextDigestAfterValidationV2(context, offer)
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKStatementDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
	_ = cvWriteBytes(&wire, context.ReceiverRegistryDigest)
	cvWritePoint(&wire, &offer.Evaluation)
	_ = cvWriteBytes(&wire, ciphertextDigest)
	ownershipWire, err := cvOwnershipProofV2CanonicalBytesMode(&offer.Ownership, context, validatePoints)
	if err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, ownershipWire)
	return hashBytes([]byte(cvACKStatementDomainV2), wire.Bytes()), nil
}

func cvCiphertextDigestV2(context *cvLeafContextV2, offer *cvReceiverLaneOfferV2) ([]byte, error) {
	return cvCiphertextDigestModeV2(context, offer, true)
}

func cvCiphertextDigestAfterValidationV2(
	context *cvLeafContextV2, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	return cvCiphertextDigestModeV2(context, offer, false)
}

func cvCiphertextDigestModeV2(
	context *cvLeafContextV2, offer *cvReceiverLaneOfferV2, validatePoints bool,
) ([]byte, error) {
	if context == nil || offer == nil {
		return nil, fmt.Errorf("invalid CV V2 ciphertext digest")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCiphertextDigestDomainV2))
	if len(offer.ScalarChunks) != chunks || (validatePoints && !cvValidCiphertext(&offer.Blinding)) {
		return nil, fmt.Errorf("invalid CV V2 ciphertext digest dimensions")
	}
	if err := cvWriteUint32(&wire, len(offer.ScalarChunks)); err != nil {
		return nil, err
	}
	for chunk := range offer.ScalarChunks {
		if validatePoints && !cvValidCiphertext(&offer.ScalarChunks[chunk]) {
			return nil, fmt.Errorf("invalid CV V2 scalar ciphertext")
		}
		cvWriteCiphertext(&wire, &offer.ScalarChunks[chunk])
	}
	cvWriteCiphertext(&wire, &offer.Blinding)
	return hashBytes([]byte(cvCiphertextDigestDomainV2), wire.Bytes()), nil
}

func cvReceiverLaneOfferV2CanonicalBytes(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer")
	}
	return cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealerID, offer)
}

func cvReceiverLaneOfferV2CanonicalBytesAfterValidation(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	if context == nil || dealerID < 0 || offer == nil || offer.ReceiverID < 0 || offer.ReceiverIndex <= 0 {
		return nil, fmt.Errorf("invalid verified CV V2 lane offer")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || len(offer.ScalarChunks) != chunks {
		return nil, fmt.Errorf("invalid verified CV V2 lane offer dimensions")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	proofWire, err := cvOwnershipProofV2CanonicalBytesAfterValidation(&offer.Ownership, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneOfferWireDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	if err := cvWriteUint32(&wire, offer.ReceiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &offer.Evaluation)
	if err := cvWriteUint32(&wire, len(offer.ScalarChunks)); err != nil {
		return nil, err
	}
	for chunk := range offer.ScalarChunks {
		cvWriteCiphertext(&wire, &offer.ScalarChunks[chunk])
	}
	cvWriteCiphertext(&wire, &offer.Blinding)
	_ = cvWriteBytes(&wire, proofWire)
	return wire.Bytes(), nil
}

func cvDecodeReceiverLaneOfferV2(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	return cvDecodeReceiverLaneOfferV2Mode(
		wire, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey, true, nil,
	)
}

func cvDecodeReceiverLaneOfferBeforeVerificationV2(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	return cvDecodeReceiverLaneOfferBeforeVerificationV2Sidechannel(
		wire, nil, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey,
	)
}

func cvDecodeReceiverLaneOfferBeforeVerificationV2Sidechannel(
	wire []byte, side *cvDecodeSidechannelV2, context *cvLeafContextV2,
	expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	return cvDecodeReceiverLaneOfferV2Mode(
		wire, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey, false, side,
	)
}

func cvDecodeReceiverLaneOfferV2Mode(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine, verifyOwnership bool, side *cvDecodeSidechannelV2,
) (*cvReceiverLaneOfferV2, error) {
	if expectedDealer < 0 || cvValidateReceiverBindingV2(
		context, expectedReceiverID, expectedReceiverIndex, receiverPublicKey,
	) != nil {
		return nil, fmt.Errorf("invalid expected CV V2 lane offer binding")
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvLaneOfferWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneOfferWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 lane offer domain")
	}
	contextDigest, err := r.bytes(32)
	expectedContextDigest, digestErr := cvLeafContextDigestV2(context)
	if err != nil || digestErr != nil || !bytes.Equal(contextDigest, expectedContextDigest) {
		return nil, fmt.Errorf("invalid CV V2 lane offer context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer != uint64(expectedDealer) {
		return nil, fmt.Errorf("invalid CV V2 lane offer dealer")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID != uint64(expectedReceiverID) {
		return nil, fmt.Errorf("invalid CV V2 lane offer receiver")
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex != expectedReceiverIndex {
		return nil, fmt.Errorf("invalid CV V2 lane offer receiver index")
	}
	evaluation, err := r.pointDeferred()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer evaluation")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	offer := &cvReceiverLaneOfferV2{
		ReceiverID: expectedReceiverID, ReceiverIndex: expectedReceiverIndex, Evaluation: evaluation,
		ScalarChunks: make([]cvElGamalCiphertext, chunks),
	}
	count, err := r.uint32()
	if err != nil || count != chunks {
		return nil, fmt.Errorf("invalid CV V2 scalar chunk count")
	}
	for chunk := 0; chunk < chunks; chunk++ {
		offer.ScalarChunks[chunk], err = r.ciphertextDeferred()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 scalar ciphertext")
		}
	}
	offer.Blinding, err = r.ciphertextDeferred()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 blinding ciphertext")
	}
	if err := r.assertDecodedSubgroup(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer point: %w", err)
	}
	proofWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 lane offer proof framing")
	}
	proof, err := cvDecodeOwnershipProofV2Sidechannel(proofWire, side, context)
	if err != nil {
		return nil, err
	}
	offer.Ownership = *proof
	var canonical []byte
	if verifyOwnership {
		canonical, err = cvReceiverLaneOfferV2CanonicalBytes(context, expectedDealer, offer, receiverPublicKey)
	} else {
		canonical, err = cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, expectedDealer, offer)
	}
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane offer")
	}
	return offer, nil
}

func cvOwnershipProofV2CanonicalBytes(proof *cvOwnershipProofV2, context *cvLeafContextV2) ([]byte, error) {
	return cvOwnershipProofV2CanonicalBytesMode(proof, context, true)
}

func cvOwnershipProofV2CanonicalBytesAfterValidation(
	proof *cvOwnershipProofV2, context *cvLeafContextV2,
) ([]byte, error) {
	return cvOwnershipProofV2CanonicalBytesMode(proof, context, false)
}

func cvOwnershipProofV2CanonicalBytesMode(
	proof *cvOwnershipProofV2, context *cvLeafContextV2, validatePoints bool,
) ([]byte, error) {
	if context == nil || proof == nil {
		return nil, fmt.Errorf("invalid CV V2 ownership proof")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	if len(proof.ScalarCoinCommitments) != chunks || len(proof.ScalarCipherCommitments) != chunks ||
		len(proof.ScalarCoinResponses) != chunks || len(proof.ScalarDigitResponses) != chunks ||
		(validatePoints && (!cvValidG1(&proof.BlindingCoinCommitment, true) ||
			!cvValidG1(&proof.BlindingCipherCommitment, true) ||
			!cvValidG1(&proof.EvaluationCommitment, true))) {
		return nil, fmt.Errorf("invalid CV V2 ownership proof dimensions")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvOwnershipProofWireDomainV2))
	if err := cvWritePointVectorMode(&wire, proof.ScalarCoinCommitments, validatePoints); err != nil {
		return nil, err
	}
	if err := cvWritePointVectorMode(&wire, proof.ScalarCipherCommitments, validatePoints); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &proof.BlindingCoinCommitment)
	cvWritePoint(&wire, &proof.BlindingCipherCommitment)
	cvWritePoint(&wire, &proof.EvaluationCommitment)
	if err := cvWriteScalarVector(&wire, proof.ScalarCoinResponses); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.ScalarDigitResponses); err != nil {
		return nil, err
	}
	cvWriteScalar(&wire, &proof.BlindingCoinResponse)
	cvWriteScalar(&wire, &proof.BlindingShareResponse)
	return wire.Bytes(), nil
}

func cvDecodeOwnershipProofV2(wire []byte, context *cvLeafContextV2) (*cvOwnershipProofV2, error) {
	return cvDecodeOwnershipProofV2Sidechannel(wire, nil, context)
}

func cvDecodeOwnershipProofV2Sidechannel(
	wire []byte, side *cvDecodeSidechannelV2, context *cvLeafContextV2,
) (*cvOwnershipProofV2, error) {
	if context == nil {
		return nil, fmt.Errorf("nil CV V2 ownership context")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvOwnershipProofWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvOwnershipProofWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 ownership proof domain")
	}
	coinCommitments, err := cvReadExactPointVectorDeferred(r, chunks, "V2 ownership scalar coin commitments")
	if err != nil {
		return nil, err
	}
	cipherCommitments, err := cvReadExactPointVectorDeferred(r, chunks, "V2 ownership scalar ciphertext commitments")
	if err != nil {
		return nil, err
	}
	blindingCoinCommitment, err := r.pointDeferred()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership blinding coin commitment")
	}
	blindingCipherCommitment, err := r.pointDeferred()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership blinding ciphertext commitment")
	}
	evaluationCommitment, err := r.pointDeferred()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership evaluation commitment")
	}
	coinResponses, err := cvReadExactScalarVectorV2(r, chunks)
	if err != nil {
		return nil, err
	}
	digitResponses, err := cvReadExactScalarVectorV2(r, chunks)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership proof response framing")
	}
	blindingCoinResponse, err := r.scalar()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership blinding coin response")
	}
	blindingShareResponse, err := r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 ownership blinding share response")
	}
	proof := &cvOwnershipProofV2{
		ScalarCoinCommitments: coinCommitments, ScalarCipherCommitments: cipherCommitments,
		BlindingCoinCommitment: blindingCoinCommitment, BlindingCipherCommitment: blindingCipherCommitment,
		EvaluationCommitment: evaluationCommitment, ScalarCoinResponses: coinResponses,
		ScalarDigitResponses: digitResponses, BlindingCoinResponse: blindingCoinResponse,
		BlindingShareResponse: blindingShareResponse,
	}
	if err := r.assertDecodedSubgroup(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership proof point: %w", err)
	}
	canonical, err := cvOwnershipProofV2CanonicalBytesAfterValidation(proof, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ownership proof")
	}
	return proof, nil
}

func cvACKEvidenceV2CanonicalBytes(evidence *cvACKEvidenceV2, context *cvLeafContextV2) ([]byte, error) {
	return cvACKEvidenceV2CanonicalBytesMode(evidence, context, true)
}

func cvACKEvidenceV2CanonicalBytesAfterValidation(
	evidence *cvACKEvidenceV2, context *cvLeafContextV2,
) ([]byte, error) {
	return cvACKEvidenceV2CanonicalBytesMode(evidence, context, false)
}

func cvACKEvidenceV2CanonicalBytesMode(
	evidence *cvACKEvidenceV2, context *cvLeafContextV2, validatePoints bool,
) ([]byte, error) {
	if evidence == nil || len(evidence.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid CV V2 ACK evidence")
	}
	ownershipWire, err := cvOwnershipProofV2CanonicalBytesMode(&evidence.Ownership, context, validatePoints)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKWireDomainV2))
	_ = cvWriteBytes(&wire, ownershipWire)
	_ = cvWriteBytes(&wire, evidence.Signature)
	return wire.Bytes(), nil
}

func cvDecodeACKEvidenceV2(wire []byte, context *cvLeafContextV2) (*cvACKEvidenceV2, error) {
	return cvDecodeACKEvidenceV2Sidechannel(wire, nil, context)
}

func cvDecodeACKEvidenceV2Sidechannel(
	wire []byte, side *cvDecodeSidechannelV2, context *cvLeafContextV2,
) (*cvACKEvidenceV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvACKWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvACKWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 ACK domain")
	}
	ownershipWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ACK ownership proof")
	}
	ownership, err := cvDecodeOwnershipProofV2Sidechannel(ownershipWire, side, context)
	if err != nil {
		return nil, err
	}
	signature, err := r.bytes(ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 ACK signature framing")
	}
	evidence := &cvACKEvidenceV2{Ownership: *ownership, Signature: signature}
	canonical, err := cvACKEvidenceV2CanonicalBytesAfterValidation(evidence, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ACK evidence")
	}
	return evidence, nil
}

func cvCloneOwnershipProofV2(proof *cvOwnershipProofV2) cvOwnershipProofV2 {
	if proof == nil {
		return cvOwnershipProofV2{}
	}
	return cvOwnershipProofV2{
		ScalarCoinCommitments:    append([]bls12381.G1Affine(nil), proof.ScalarCoinCommitments...),
		ScalarCipherCommitments:  append([]bls12381.G1Affine(nil), proof.ScalarCipherCommitments...),
		BlindingCoinCommitment:   proof.BlindingCoinCommitment,
		BlindingCipherCommitment: proof.BlindingCipherCommitment,
		EvaluationCommitment:     proof.EvaluationCommitment,
		ScalarCoinResponses:      append([]fr.Element(nil), proof.ScalarCoinResponses...),
		ScalarDigitResponses:     append([]fr.Element(nil), proof.ScalarDigitResponses...),
		BlindingCoinResponse:     proof.BlindingCoinResponse,
		BlindingShareResponse:    proof.BlindingShareResponse,
	}
}

func cvEqualOwnershipProofV2(left, right *cvOwnershipProofV2) bool {
	if left == nil || right == nil || len(left.ScalarCoinCommitments) != len(right.ScalarCoinCommitments) ||
		len(left.ScalarCipherCommitments) != len(right.ScalarCipherCommitments) ||
		len(left.ScalarCoinResponses) != len(right.ScalarCoinResponses) ||
		len(left.ScalarDigitResponses) != len(right.ScalarDigitResponses) ||
		!left.BlindingCoinCommitment.Equal(&right.BlindingCoinCommitment) ||
		!left.BlindingCipherCommitment.Equal(&right.BlindingCipherCommitment) ||
		!left.EvaluationCommitment.Equal(&right.EvaluationCommitment) ||
		!left.BlindingCoinResponse.Equal(&right.BlindingCoinResponse) ||
		!left.BlindingShareResponse.Equal(&right.BlindingShareResponse) {
		return false
	}
	for i := range left.ScalarCoinCommitments {
		if !left.ScalarCoinCommitments[i].Equal(&right.ScalarCoinCommitments[i]) {
			return false
		}
	}
	for i := range left.ScalarCipherCommitments {
		if !left.ScalarCipherCommitments[i].Equal(&right.ScalarCipherCommitments[i]) {
			return false
		}
	}
	for i := range left.ScalarCoinResponses {
		if !left.ScalarCoinResponses[i].Equal(&right.ScalarCoinResponses[i]) {
			return false
		}
	}
	for i := range left.ScalarDigitResponses {
		if !left.ScalarDigitResponses[i].Equal(&right.ScalarDigitResponses[i]) {
			return false
		}
	}
	return true
}
