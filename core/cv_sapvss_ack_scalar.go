package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLaneOfferWireDomainScalar      = "ARL-CV-sAPVSS/v2-scalar-group/lane-offer"
	cvFallbackLaneWireDomainScalar   = "ARL-CV-sAPVSS/v2-scalar-group/fallback-lane"
	cvOwnershipProofWireDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/ownership-proof"
	cvACKWireDomainScalar            = "ARL-CV-sAPVSS/v2-scalar-group/ack"
	cvACKStatementDomainScalar       = "ARL-CV-sAPVSS/v2-scalar-group/ack-statement"
	cvCiphertextDigestDomainScalar   = "ARL-CV-sAPVSS/v2-scalar-group/ciphertexts"
)

type cvACKEvidenceScalar struct {
	Ownership cvOwnershipProofScalar
	Signature []byte
}

func cvFallbackLaneOfferScalarCanonicalBytes(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvValidateLaneOfferShapeScalar(context, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback lane")
	}
	return cvFallbackLaneOfferScalarCanonicalBytesAfterValidation(context, dealerID, offer)
}

func cvFallbackLaneOfferScalarCanonicalBytesAfterValidation(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
) ([]byte, error) {
	if context == nil || dealerID < 0 || offer == nil || offer.ReceiverID < 0 || offer.ReceiverIndex <= 0 {
		return nil, fmt.Errorf("invalid verified CV V2 fallback lane")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || len(offer.ScalarChunks) != chunks {
		return nil, fmt.Errorf("invalid verified CV V2 fallback lane dimensions")
	}
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackLaneWireDomainScalar))
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

func cvDecodeFallbackLaneOfferScalar(
	wire []byte, context *cvLeafContextScalar, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
) (*cvReceiverLaneOfferScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackLaneWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackLaneWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane domain")
	}
	contextDigest, err := r.bytes(32)
	wantContext, contextErr := cvLeafContextDigestScalar(context)
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
	offer := &cvReceiverLaneOfferScalar{
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
	canonical, err := cvFallbackLaneOfferScalarCanonicalBytesAfterValidation(context, expectedDealer, offer)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback lane")
	}
	return offer, nil
}

func cvVerifyDecryptAndSignACKScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey,
) (*cvACKEvidenceScalar, fr.Element, bls12381.G1Affine, error) {
	return cvVerifyDecryptAndSignACKModeScalar(
		context, dealerID, offer, receiverPublicKey, receiverSecret,
		identityPublicKey, identitySecret, true,
	)
}

func cvVerifyDecryptAndSignACKAfterPointDecodingScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey,
) (*cvACKEvidenceScalar, fr.Element, bls12381.G1Affine, error) {
	return cvVerifyDecryptAndSignACKModeScalar(
		context, dealerID, offer, receiverPublicKey, receiverSecret,
		identityPublicKey, identitySecret, false,
	)
}

func cvVerifyDecryptAndSignACKModeScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey, validatePoints bool,
) (*cvACKEvidenceScalar, fr.Element, bls12381.G1Affine, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize || len(identitySecret) != ed25519.PrivateKeySize ||
		!bytes.Equal(identitySecret.Public().(ed25519.PublicKey), identityPublicKey) {
		return nil, fr.Element{}, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 receiver identity secret")
	}
	var scalar fr.Element
	var blinding bls12381.G1Affine
	var err error
	if validatePoints {
		scalar, blinding, err = cvVerifyAndDecryptReceiverLanesScalar(
			context, dealerID, offer, receiverPublicKey, receiverSecret,
		)
	} else {
		scalar, blinding, err = cvVerifyAndDecryptReceiverLanesAfterPointDecodingScalar(
			context, dealerID, offer, receiverPublicKey, receiverSecret,
		)
	}
	if err != nil {
		return nil, fr.Element{}, bls12381.G1Affine{}, err
	}
	statement, err := cvACKStatementAfterValidationScalar(context, dealerID, offer)
	if err != nil {
		return nil, fr.Element{}, bls12381.G1Affine{}, err
	}
	evidence := &cvACKEvidenceScalar{
		Ownership: cvCloneOwnershipProofScalar(&offer.Ownership),
		Signature: ed25519.Sign(identitySecret, statement),
	}
	return evidence, scalar, blinding, nil
}

func cvVerifyACKScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceScalar,
) error {
	return cvVerifyACKModeScalar(context, dealerID, offer, receiverPublicKey, identityPublicKey, evidence, true)
}

func cvVerifyACKAfterLocalOwnershipValidationScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	identityPublicKey ed25519.PublicKey, evidence *cvACKEvidenceScalar,
) error {
	if offer == nil || evidence == nil || len(identityPublicKey) != ed25519.PublicKeySize ||
		len(evidence.Signature) != ed25519.SignatureSize ||
		!cvEqualOwnershipProofScalar(&offer.Ownership, &evidence.Ownership) {
		return fmt.Errorf("invalid verified CV V2 ACK evidence")
	}
	statement, err := cvACKStatementAfterValidationScalar(context, dealerID, offer)
	if err != nil || !ed25519.Verify(identityPublicKey, statement, evidence.Signature) {
		return fmt.Errorf("invalid CV V2 ACK signature")
	}
	return nil
}

func cvVerifyACKModeScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceScalar, validatePoints bool,
) error {
	if offer == nil || evidence == nil || len(identityPublicKey) != ed25519.PublicKeySize ||
		len(evidence.Signature) != ed25519.SignatureSize ||
		!cvEqualOwnershipProofScalar(&offer.Ownership, &evidence.Ownership) {
		return fmt.Errorf("invalid CV V2 ACK evidence")
	}
	var ownershipErr error
	if validatePoints {
		ownershipErr = cvVerifyOwnershipScalar(context, dealerID, offer, receiverPublicKey)
	} else {
		ownershipErr = cvVerifyOwnershipAfterPointDecodingScalar(context, dealerID, offer, receiverPublicKey)
	}
	if ownershipErr != nil {
		return ownershipErr
	}
	statement, err := cvACKStatementAfterValidationScalar(context, dealerID, offer)
	if err != nil || !ed25519.Verify(identityPublicKey, statement, evidence.Signature) {
		return fmt.Errorf("invalid CV V2 ACK signature")
	}
	return nil
}

func cvACKStatementAfterValidationScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
) ([]byte, error) {
	return cvACKStatementModeScalar(context, dealerID, offer, false)
}

func cvACKStatementModeScalar(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar, validatePoints bool,
) ([]byte, error) {
	if dealerID < 0 || context == nil || offer == nil || len(context.ReceiverRegistryDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 ACK statement")
	}
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		return nil, err
	}
	var ciphertextDigest []byte
	if validatePoints {
		ciphertextDigest, err = cvCiphertextDigestScalar(context, offer)
	} else {
		ciphertextDigest, err = cvCiphertextDigestAfterValidationScalar(context, offer)
	}
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKStatementDomainScalar))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
	_ = cvWriteBytes(&wire, context.ReceiverRegistryDigest)
	cvWritePoint(&wire, &offer.Evaluation)
	_ = cvWriteBytes(&wire, ciphertextDigest)
	ownershipWire, err := cvOwnershipProofScalarCanonicalBytesMode(&offer.Ownership, context, validatePoints)
	if err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, ownershipWire)
	return hashBytes([]byte(cvACKStatementDomainScalar), wire.Bytes()), nil
}

func cvCiphertextDigestScalar(context *cvLeafContextScalar, offer *cvReceiverLaneOfferScalar) ([]byte, error) {
	return cvCiphertextDigestModeScalar(context, offer, true)
}

func cvCiphertextDigestAfterValidationScalar(
	context *cvLeafContextScalar, offer *cvReceiverLaneOfferScalar,
) ([]byte, error) {
	return cvCiphertextDigestModeScalar(context, offer, false)
}

func cvCiphertextDigestModeScalar(
	context *cvLeafContextScalar, offer *cvReceiverLaneOfferScalar, validatePoints bool,
) ([]byte, error) {
	if context == nil || offer == nil {
		return nil, fmt.Errorf("invalid CV V2 ciphertext digest")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCiphertextDigestDomainScalar))
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
	return hashBytes([]byte(cvCiphertextDigestDomainScalar), wire.Bytes()), nil
}

func cvReceiverLaneOfferScalarCanonicalBytes(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvVerifyOwnershipScalar(context, dealerID, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer")
	}
	return cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(context, dealerID, offer)
}

func cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(
	context *cvLeafContextScalar, dealerID int, offer *cvReceiverLaneOfferScalar,
) ([]byte, error) {
	if context == nil || dealerID < 0 || offer == nil || offer.ReceiverID < 0 || offer.ReceiverIndex <= 0 {
		return nil, fmt.Errorf("invalid verified CV V2 lane offer")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || len(offer.ScalarChunks) != chunks {
		return nil, fmt.Errorf("invalid verified CV V2 lane offer dimensions")
	}
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		return nil, err
	}
	proofWire, err := cvOwnershipProofScalarCanonicalBytesAfterValidation(&offer.Ownership, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneOfferWireDomainScalar))
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

func cvDecodeReceiverLaneOfferScalar(
	wire []byte, context *cvLeafContextScalar, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferScalar, error) {
	return cvDecodeReceiverLaneOfferScalarMode(
		wire, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey, true, nil,
	)
}

func cvDecodeReceiverLaneOfferBeforeVerificationScalar(
	wire []byte, context *cvLeafContextScalar, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferScalar, error) {
	return cvDecodeReceiverLaneOfferBeforeVerificationScalarSidechannel(
		wire, nil, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey,
	)
}

func cvDecodeReceiverLaneOfferBeforeVerificationScalarSidechannel(
	wire []byte, side *cvDecodeSidechannelScalar, context *cvLeafContextScalar,
	expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferScalar, error) {
	return cvDecodeReceiverLaneOfferScalarMode(
		wire, context, expectedDealer, expectedReceiverID, expectedReceiverIndex, receiverPublicKey, false, side,
	)
}

func cvDecodeReceiverLaneOfferScalarMode(
	wire []byte, context *cvLeafContextScalar, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine, verifyOwnership bool, side *cvDecodeSidechannelScalar,
) (*cvReceiverLaneOfferScalar, error) {
	if expectedDealer < 0 || cvValidateReceiverBindingScalar(
		context, expectedReceiverID, expectedReceiverIndex, receiverPublicKey,
	) != nil {
		return nil, fmt.Errorf("invalid expected CV V2 lane offer binding")
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvLaneOfferWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneOfferWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 lane offer domain")
	}
	contextDigest, err := r.bytes(32)
	expectedContextDigest, digestErr := cvLeafContextDigestScalar(context)
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
	offer := &cvReceiverLaneOfferScalar{
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
	proof, err := cvDecodeOwnershipProofScalarSidechannel(proofWire, side, context)
	if err != nil {
		return nil, err
	}
	offer.Ownership = *proof
	var canonical []byte
	if verifyOwnership {
		canonical, err = cvReceiverLaneOfferScalarCanonicalBytes(context, expectedDealer, offer, receiverPublicKey)
	} else {
		canonical, err = cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(context, expectedDealer, offer)
	}
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane offer")
	}
	return offer, nil
}

func cvOwnershipProofScalarCanonicalBytesAfterValidation(
	proof *cvOwnershipProofScalar, context *cvLeafContextScalar,
) ([]byte, error) {
	return cvOwnershipProofScalarCanonicalBytesMode(proof, context, false)
}

func cvOwnershipProofScalarCanonicalBytesMode(
	proof *cvOwnershipProofScalar, context *cvLeafContextScalar, validatePoints bool,
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
	_ = cvWriteBytes(&wire, []byte(cvOwnershipProofWireDomainScalar))
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

func cvDecodeOwnershipProofScalarSidechannel(
	wire []byte, side *cvDecodeSidechannelScalar, context *cvLeafContextScalar,
) (*cvOwnershipProofScalar, error) {
	if context == nil {
		return nil, fmt.Errorf("nil CV V2 ownership context")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvOwnershipProofWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvOwnershipProofWireDomainScalar)) {
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
	coinResponses, err := cvReadExactScalarVectorScalar(r, chunks)
	if err != nil {
		return nil, err
	}
	digitResponses, err := cvReadExactScalarVectorScalar(r, chunks)
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
	proof := &cvOwnershipProofScalar{
		ScalarCoinCommitments: coinCommitments, ScalarCipherCommitments: cipherCommitments,
		BlindingCoinCommitment: blindingCoinCommitment, BlindingCipherCommitment: blindingCipherCommitment,
		EvaluationCommitment: evaluationCommitment, ScalarCoinResponses: coinResponses,
		ScalarDigitResponses: digitResponses, BlindingCoinResponse: blindingCoinResponse,
		BlindingShareResponse: blindingShareResponse,
	}
	if err := r.assertDecodedSubgroup(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 ownership proof point: %w", err)
	}
	canonical, err := cvOwnershipProofScalarCanonicalBytesAfterValidation(proof, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ownership proof")
	}
	return proof, nil
}

func cvACKEvidenceScalarCanonicalBytes(evidence *cvACKEvidenceScalar, context *cvLeafContextScalar) ([]byte, error) {
	return cvACKEvidenceScalarCanonicalBytesMode(evidence, context, true)
}

func cvACKEvidenceScalarCanonicalBytesAfterValidation(
	evidence *cvACKEvidenceScalar, context *cvLeafContextScalar,
) ([]byte, error) {
	return cvACKEvidenceScalarCanonicalBytesMode(evidence, context, false)
}

func cvACKEvidenceScalarCanonicalBytesMode(
	evidence *cvACKEvidenceScalar, context *cvLeafContextScalar, validatePoints bool,
) ([]byte, error) {
	if evidence == nil || len(evidence.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid CV V2 ACK evidence")
	}
	ownershipWire, err := cvOwnershipProofScalarCanonicalBytesMode(&evidence.Ownership, context, validatePoints)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKWireDomainScalar))
	_ = cvWriteBytes(&wire, ownershipWire)
	_ = cvWriteBytes(&wire, evidence.Signature)
	return wire.Bytes(), nil
}

func cvDecodeACKEvidenceScalar(wire []byte, context *cvLeafContextScalar) (*cvACKEvidenceScalar, error) {
	return cvDecodeACKEvidenceScalarSidechannel(wire, nil, context)
}

func cvDecodeACKEvidenceScalarSidechannel(
	wire []byte, side *cvDecodeSidechannelScalar, context *cvLeafContextScalar,
) (*cvACKEvidenceScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvACKWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvACKWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 ACK domain")
	}
	ownershipWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ACK ownership proof")
	}
	ownership, err := cvDecodeOwnershipProofScalarSidechannel(ownershipWire, side, context)
	if err != nil {
		return nil, err
	}
	signature, err := r.bytes(ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 ACK signature framing")
	}
	evidence := &cvACKEvidenceScalar{Ownership: *ownership, Signature: signature}
	canonical, err := cvACKEvidenceScalarCanonicalBytesAfterValidation(evidence, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ACK evidence")
	}
	return evidence, nil
}

func cvCloneOwnershipProofScalar(proof *cvOwnershipProofScalar) cvOwnershipProofScalar {
	if proof == nil {
		return cvOwnershipProofScalar{}
	}
	return cvOwnershipProofScalar{
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

func cvEqualOwnershipProofScalar(left, right *cvOwnershipProofScalar) bool {
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
