package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCVACKV2SignsOnlyAfterScalarGroupVerificationAndRoundTrips(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identitySecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence, recoveredScalar, recoveredBlinding, err := cvVerifyDecryptAndSignACKV2(
		context, dealer, offer, &encryptionPublic, encryptionSecret, identityPublic, identitySecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	wantBlinding := cvPointTimes(&h, &blinding)
	if !recoveredScalar.Equal(&scalar) || !recoveredBlinding.Equal(&wantBlinding) {
		t.Fatal("ACK path did not verify scalar/group openings")
	}
	if err := cvVerifyACKV2(context, dealer, offer, &encryptionPublic, identityPublic, evidence); err != nil {
		t.Fatalf("verify V2 ACK: %v", err)
	}

	offerWire, err := cvReceiverLaneOfferV2CanonicalBytes(context, dealer, offer, &encryptionPublic)
	if err != nil {
		t.Fatal(err)
	}
	decodedOffer, err := cvDecodeReceiverLaneOfferV2(
		offerWire, context, dealer, receiverID, receiverIndex, &encryptionPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	ackWire, err := cvACKEvidenceV2CanonicalBytes(evidence, context)
	if err != nil {
		t.Fatal(err)
	}
	decodedACK, err := cvDecodeACKEvidenceV2(ackWire, context)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyACKV2(context, dealer, decodedOffer, &encryptionPublic, identityPublic, decodedACK); err != nil {
		t.Fatalf("verify decoded V2 ACK: %v", err)
	}
	if _, err := cvDecodeReceiverLaneOfferV2(append(append([]byte(nil), offerWire...), 0),
		context, dealer, receiverID, receiverIndex, &encryptionPublic); err == nil {
		t.Fatal("accepted V2 lane offer with trailing bytes")
	}
	if _, err := cvDecodeACKEvidenceV2(append(append([]byte(nil), ackWire...), 0), context); err == nil {
		t.Fatal("accepted V2 ACK with trailing bytes")
	}
}

func TestCVACKV2BindsCiphertextsOwnershipAndIdentityRegistry(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identitySecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKV2(
		context, dealer, offer, &encryptionPublic, encryptionSecret, identityPublic, identitySecret,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, wrongIdentity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyACKV2(context, dealer, offer, &encryptionPublic,
		wrongIdentity.Public().(ed25519.PublicKey), evidence); err == nil {
		t.Fatal("accepted V2 ACK under another receiver identity key")
	}
	badSignature := *evidence
	badSignature.Signature = append([]byte(nil), evidence.Signature...)
	badSignature.Signature[0] ^= 1
	if err := cvVerifyACKV2(context, dealer, offer, &encryptionPublic, identityPublic, &badSignature); err == nil {
		t.Fatal("accepted mutated V2 ACK signature")
	}
	badOwnership := *evidence
	badOwnership.Ownership = cvCloneOwnershipProofV2(&evidence.Ownership)
	badOwnership.Ownership.ScalarCoinResponses[0].SetZero()
	if err := cvVerifyACKV2(context, dealer, offer, &encryptionPublic, identityPublic, &badOwnership); err == nil {
		t.Fatal("accepted ACK evidence carrying different ownership proof")
	}

	badOffer := *offer
	badOffer.Blinding.c.Add(&badOffer.Blinding.c, &genG1)
	if err := cvVerifyACKV2(context, dealer, &badOffer, &encryptionPublic, identityPublic, evidence); err == nil {
		t.Fatal("accepted ACK after ciphertext mutation")
	}
}

func TestCVACKV2RejectsEncryptionSecretAsIdentitySecretAndInvalidOfferBeforeSigning(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	encryptionBytes := encryptionSecret.Bytes()
	if _, _, _, err := cvVerifyDecryptAndSignACKV2(
		context, dealer, offer, &encryptionPublic, encryptionSecret, make(ed25519.PublicKey, ed25519.PublicKeySize),
		ed25519.PrivateKey(encryptionBytes[:]),
	); err == nil {
		t.Fatal("used ElGamal decryption secret as V2 ACK identity secret")
	}
	_, identitySecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badOffer := *offer
	badOffer.Ownership = cvCloneOwnershipProofV2(&offer.Ownership)
	badOffer.Ownership.ScalarDigitResponses[0].SetZero()
	if _, _, _, err := cvVerifyDecryptAndSignACKV2(
		context, dealer, &badOffer, &encryptionPublic, encryptionSecret,
		identitySecret.Public().(ed25519.PublicKey), identitySecret,
	); err == nil {
		t.Fatal("signed ACK before rejecting invalid ownership proof")
	}
}
