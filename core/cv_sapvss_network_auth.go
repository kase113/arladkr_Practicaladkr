package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvNetworkAuthDomain  = "ARL-CV-sAPVSS/network-auth"
	cvNetworkAuthVersion = byte(1)
	cvNetworkAuthBytes   = 1 + 4 + bls12381.SizeOfG1AffineCompressed + fr.Bytes
)

type cvNetworkAuthenticator struct {
	oldPublicKeys        map[int]bls12381.G1Affine
	oldLocalSecrets      map[int]fr.Element
	receiverPublicKeys   map[int]bls12381.G1Affine
	receiverLocalSecrets map[int]fr.Element
}

func newCVNetworkAuthenticator(
	oldSigner *tblsThresholdSigner,
	receiverOrder []int,
	receiverPublicKeys []bls12381.G1Affine,
	localReceiverSecrets map[int]fr.Element,
) (*cvNetworkAuthenticator, error) {
	if oldSigner == nil || len(oldSigner.memberOrder) == 0 ||
		len(oldSigner.transportPubKeyShares) != len(oldSigner.memberOrder) ||
		len(receiverOrder) != len(receiverPublicKeys) {
		return nil, fmt.Errorf("invalid CV network authentication material")
	}
	auth := &cvNetworkAuthenticator{
		oldPublicKeys:        make(map[int]bls12381.G1Affine, len(oldSigner.memberOrder)),
		oldLocalSecrets:      make(map[int]fr.Element),
		receiverPublicKeys:   make(map[int]bls12381.G1Affine, len(receiverOrder)),
		receiverLocalSecrets: make(map[int]fr.Element),
	}
	for i, member := range oldSigner.memberOrder {
		if !cvValidG1(&oldSigner.transportPubKeyShares[i], false) {
			return nil, fmt.Errorf("invalid old-node transport public key for %d", member)
		}
		auth.oldPublicKeys[member] = oldSigner.transportPubKeyShares[i]
		if oldSigner.signingMembers == nil {
			auth.oldLocalSecrets[member] = oldSigner.shares[i]
		} else if _, local := oldSigner.signingMembers[member]; local {
			auth.oldLocalSecrets[member] = oldSigner.shares[i]
		}
	}
	for i, receiver := range receiverOrder {
		if !cvValidG1(&receiverPublicKeys[i], false) {
			return nil, fmt.Errorf("invalid CV receiver transport key for %d", receiver)
		}
		auth.receiverPublicKeys[receiver] = receiverPublicKeys[i]
		if secret, local := localReceiverSecrets[receiver]; local {
			if secret.IsZero() {
				return nil, fmt.Errorf("invalid local receiver transport secret for %d", receiver)
			}
			var public bls12381.G1Affine
			public.ScalarMultiplication(&genG1, secret.BigInt(new(big.Int)))
			if !public.Equal(&receiverPublicKeys[i]) {
				return nil, fmt.Errorf("receiver transport secret/public mismatch for %d", receiver)
			}
			auth.receiverLocalSecrets[receiver] = secret
		}
	}
	return auth, nil
}

func (a *cvNetworkAuthenticator) actorKeys(
	actor int,
	tag string,
) (bls12381.G1Affine, fr.Element, bool, bool) {
	if tag == apvssTagLaneACK {
		public, registered := a.receiverPublicKeys[actor]
		secret, local := a.receiverLocalSecrets[actor]
		return public, secret, registered, local
	}
	public, registered := a.oldPublicKeys[actor]
	secret, local := a.oldLocalSecrets[actor]
	return public, secret, registered, local
}

func cvNetworkAuthDigest(from, to int, tag string, envelope []byte) ([]byte, error) {
	if from < 0 || to < 0 || tag == "" || len(tag) > tcpMessageMaxTagBytes || len(envelope) == 0 {
		return nil, fmt.Errorf("invalid CV network authentication statement")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvNetworkAuthDomain))
	cvWriteUint64(&wire, uint64(from))
	cvWriteUint64(&wire, uint64(to))
	_ = cvWriteBytes(&wire, []byte(tag))
	_ = cvWriteBytes(&wire, envelope)
	return hashBytes([]byte(cvNetworkAuthDomain), wire.Bytes()), nil
}

func (a *cvNetworkAuthenticator) seal(from, to int, tag string, envelope []byte) ([]byte, error) {
	if a == nil {
		return append([]byte(nil), envelope...), nil
	}
	_, secret, _, local := a.actorKeys(from, tag)
	if !local || secret.IsZero() {
		return nil, fmt.Errorf("CV network actor %d has no local authentication secret", from)
	}
	digest, err := cvNetworkAuthDigest(from, to, tag, envelope)
	if err != nil {
		return nil, err
	}
	var nonce fr.Element
	for nonce.IsZero() {
		if _, err := nonce.SetRandom(); err != nil {
			return nil, err
		}
	}
	var noncePoint bls12381.G1Affine
	noncePoint.ScalarMultiplication(&genG1, nonce.BigInt(new(big.Int)))
	nonceBytes := noncePoint.Bytes()
	challenge, err := cvHashToFr(cvNetworkAuthDomain+"/challenge", digest, nonceBytes[:])
	if err != nil {
		return nil, err
	}
	var response, term fr.Element
	term.Mul(&challenge, &secret)
	response.Add(&nonce, &term)
	responseBytes := response.Bytes()
	wire := make([]byte, cvNetworkAuthBytes+len(envelope))
	wire[0] = cvNetworkAuthVersion
	putUint32(wire[1:5], len(envelope))
	copy(wire[5:5+len(envelope)], envelope)
	offset := 5 + len(envelope)
	copy(wire[offset:offset+len(nonceBytes)], nonceBytes[:])
	copy(wire[offset+len(nonceBytes):], responseBytes[:])
	return wire, nil
}

func (a *cvNetworkAuthenticator) open(from, to int, tag string, wire []byte) ([]byte, error) {
	if a == nil {
		return append([]byte(nil), wire...), nil
	}
	public, _, registered, _ := a.actorKeys(from, tag)
	if !registered || len(wire) < cvNetworkAuthBytes || wire[0] != cvNetworkAuthVersion {
		return nil, fmt.Errorf("missing or invalid CV network authentication")
	}
	envelopeBytes := int(readUint32(wire[1:5]))
	if envelopeBytes <= 0 || envelopeBytes != len(wire)-cvNetworkAuthBytes {
		return nil, fmt.Errorf("invalid CV network authentication framing")
	}
	envelope := wire[5 : 5+envelopeBytes]
	offset := 5 + envelopeBytes
	var noncePoint bls12381.G1Affine
	consumed, err := noncePoint.SetBytes(wire[offset : offset+bls12381.SizeOfG1AffineCompressed])
	if err != nil || consumed != bls12381.SizeOfG1AffineCompressed || !cvValidG1(&noncePoint, false) {
		return nil, fmt.Errorf("invalid CV network authentication nonce")
	}
	var response fr.Element
	if err := response.SetBytesCanonical(wire[offset+bls12381.SizeOfG1AffineCompressed:]); err != nil {
		return nil, fmt.Errorf("invalid CV network authentication response")
	}
	digest, err := cvNetworkAuthDigest(from, to, tag, envelope)
	if err != nil {
		return nil, err
	}
	nonceBytes := noncePoint.Bytes()
	challenge, err := cvHashToFr(cvNetworkAuthDomain+"/challenge", digest, nonceBytes[:])
	if err != nil {
		return nil, err
	}
	var lhs, publicTerm, rhs bls12381.G1Affine
	lhs.ScalarMultiplication(&genG1, response.BigInt(new(big.Int)))
	publicTerm.ScalarMultiplication(&public, challenge.BigInt(new(big.Int)))
	rhs.Add(&noncePoint, &publicTerm)
	if !lhs.Equal(&rhs) {
		return nil, fmt.Errorf("invalid CV network actor signature")
	}
	return append([]byte(nil), envelope...), nil
}

func putUint32(dst []byte, value int) {
	dst[0] = byte(uint32(value) >> 24)
	dst[1] = byte(uint32(value) >> 16)
	dst[2] = byte(uint32(value) >> 8)
	dst[3] = byte(value)
}

func readUint32(src []byte) uint32 {
	return uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
}
