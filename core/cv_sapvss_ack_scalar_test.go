package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCVACKScalarSignsOnlyAfterScalarGroupVerificationAndRoundTrips(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesScalarFixture(t)
	offer, _, err := cvEncryptReceiverLanesScalar(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identitySecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence, recoveredScalar, recoveredBlinding, err := cvVerifyDecryptAndSignACKScalar(
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
	if err := cvVerifyACKScalar(context, dealer, offer, &encryptionPublic, identityPublic, evidence); err != nil {
		t.Fatalf("verify V2 ACK: %v", err)
	}

	offerWire, err := cvReceiverLaneOfferScalarCanonicalBytes(context, dealer, offer, &encryptionPublic)
	if err != nil {
		t.Fatal(err)
	}
	decodedOffer, err := cvDecodeReceiverLaneOfferScalar(
		offerWire, context, dealer, receiverID, receiverIndex, &encryptionPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	ackWire, err := cvACKEvidenceScalarCanonicalBytes(evidence, context)
	if err != nil {
		t.Fatal(err)
	}
	decodedACK, err := cvDecodeACKEvidenceScalar(ackWire, context)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyACKScalar(context, dealer, decodedOffer, &encryptionPublic, identityPublic, decodedACK); err != nil {
		t.Fatalf("verify decoded V2 ACK: %v", err)
	}
	if _, err := cvDecodeReceiverLaneOfferScalar(append(append([]byte(nil), offerWire...), 0),
		context, dealer, receiverID, receiverIndex, &encryptionPublic); err == nil {
		t.Fatal("accepted V2 lane offer with trailing bytes")
	}
	if _, err := cvDecodeACKEvidenceScalar(append(append([]byte(nil), ackWire...), 0), context); err == nil {
		t.Fatal("accepted V2 ACK with trailing bytes")
	}
}

func TestCVACKScalarBindsCiphertextsOwnershipAndIdentityRegistry(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesScalarFixture(t)
	offer, _, err := cvEncryptReceiverLanesScalar(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identitySecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKScalar(
		context, dealer, offer, &encryptionPublic, encryptionSecret, identityPublic, identitySecret,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, wrongIdentity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyACKScalar(context, dealer, offer, &encryptionPublic,
		wrongIdentity.Public().(ed25519.PublicKey), evidence); err == nil {
		t.Fatal("accepted V2 ACK under another receiver identity key")
	}
	badSignature := *evidence
	badSignature.Signature = append([]byte(nil), evidence.Signature...)
	badSignature.Signature[0] ^= 1
	if err := cvVerifyACKScalar(context, dealer, offer, &encryptionPublic, identityPublic, &badSignature); err == nil {
		t.Fatal("accepted mutated V2 ACK signature")
	}
	badOwnership := *evidence
	badOwnership.Ownership = cvCloneOwnershipProofScalar(&evidence.Ownership)
	badOwnership.Ownership.ScalarCoinResponses[0].SetZero()
	if err := cvVerifyACKScalar(context, dealer, offer, &encryptionPublic, identityPublic, &badOwnership); err == nil {
		t.Fatal("accepted ACK evidence carrying different ownership proof")
	}

	badOffer := *offer
	badOffer.Blinding.c.Add(&badOffer.Blinding.c, &genG1)
	if err := cvVerifyACKScalar(context, dealer, &badOffer, &encryptionPublic, identityPublic, evidence); err == nil {
		t.Fatal("accepted ACK after ciphertext mutation")
	}
}

func TestCVACKScalarRejectsEncryptionSecretAsIdentitySecretAndInvalidOfferBeforeSigning(t *testing.T) {
	context, dealer, receiverID, receiverIndex, encryptionSecret, encryptionPublic, scalar, blinding :=
		cvReceiverLanesScalarFixture(t)
	offer, _, err := cvEncryptReceiverLanesScalar(
		context, dealer, receiverID, receiverIndex, &encryptionPublic, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	encryptionBytes := encryptionSecret.Bytes()
	if _, _, _, err := cvVerifyDecryptAndSignACKScalar(
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
	badOffer.Ownership = cvCloneOwnershipProofScalar(&offer.Ownership)
	badOffer.Ownership.ScalarDigitResponses[0].SetZero()
	if _, _, _, err := cvVerifyDecryptAndSignACKScalar(
		context, dealer, &badOffer, &encryptionPublic, encryptionSecret,
		identitySecret.Public().(ed25519.PublicKey), identitySecret,
	); err == nil {
		t.Fatal("signed ACK before rejecting invalid ownership proof")
	}
}
