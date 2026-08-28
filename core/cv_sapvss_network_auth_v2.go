package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvNetworkAuthV2Version      = byte(2)
	cvNetworkAuthV2OldAlgorithm = byte(1)
	cvNetworkAuthV2NewAlgorithm = byte(2)
	cvNetworkAuthV2Domain       = "ARL-CV-sAPVSS/v2-scalar-group/network-auth"
	cvNetworkAuthV2OldBLSDomain = "ARL-CV-sAPVSS/v2-scalar-group/network-auth/old-bls"
	cvNetworkAuthV2HeaderBytes  = 1 + 1 + 4
	cvNetworkAuthV2CacheLimit   = 4096
)

type cvNetworkAuthenticatorV2 struct {
	sid                  string
	epoch                uint64
	oldPublicKeys        map[int]bls12381.G2Affine
	oldLocalSecrets      map[int]fr.Element
	receiverPublicKeys   map[int]ed25519.PublicKey
	receiverLocalSecrets map[int]ed25519.PrivateKey
	cacheMu              sync.Mutex
	sealed               map[string][]byte
	opened               map[string]struct{}
}

func newCVNetworkAuthenticatorV2(
	validators *cvValidatorKeyMaterialV2, receivers *cvReceiverKeyMaterialV2,
) (*cvNetworkAuthenticatorV2, error) {
	if validators == nil || receivers == nil || validators.sid == "" || validators.epoch == 0 ||
		validators.sid != receivers.sid || validators.epoch != receivers.epoch ||
		len(validators.memberOrder) != len(validators.publicKeys) || len(receivers.receiverOrder) != len(receivers.identityPublicKeys) {
		return nil, fmt.Errorf("invalid CV V2 network authentication material")
	}
	auth := &cvNetworkAuthenticatorV2{
		sid: validators.sid, epoch: validators.epoch,
		oldPublicKeys:        make(map[int]bls12381.G2Affine, len(validators.memberOrder)),
		oldLocalSecrets:      make(map[int]fr.Element, len(validators.localSecrets)),
		receiverPublicKeys:   make(map[int]ed25519.PublicKey, len(receivers.receiverOrder)),
		receiverLocalSecrets: make(map[int]ed25519.PrivateKey, len(receivers.localIdentitySecrets)),
		sealed:               make(map[string][]byte),
		opened:               make(map[string]struct{}),
	}
	for i, member := range validators.memberOrder {
		if !cvValidG2(&validators.publicKeys[i]) {
			return nil, fmt.Errorf("invalid CV V2 old-member network public key")
		}
		auth.oldPublicKeys[member] = validators.publicKeys[i]
		if secret, local := validators.localSecrets[member]; local {
			if secret.IsZero() {
				return nil, fmt.Errorf("invalid CV V2 local old-member network secret")
			}
			auth.oldLocalSecrets[member] = secret
		}
	}
	for i, receiver := range receivers.receiverOrder {
		publicKey := receivers.identityPublicKeys[i]
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid CV V2 receiver network public key")
		}
		auth.receiverPublicKeys[receiver] = append(ed25519.PublicKey(nil), publicKey...)
		if secret, local := receivers.localIdentitySecrets[receiver]; local {
			if len(secret) != ed25519.PrivateKeySize || !bytes.Equal(secret.Public().(ed25519.PublicKey), publicKey) {
				return nil, fmt.Errorf("invalid CV V2 local receiver network secret")
			}
			auth.receiverLocalSecrets[receiver] = append(ed25519.PrivateKey(nil), secret...)
		}
	}
	return auth, nil
}

func (a *cvNetworkAuthenticatorV2) seal(from, to int, tag string, envelope []byte) ([]byte, error) {
	if a == nil || a.sid == "" || a.epoch == 0 {
		return nil, fmt.Errorf("missing CV V2 network authenticator")
	}
	digest, err := cvNetworkAuthDigestV2(a.sid, a.epoch, from, to, tag, envelope)
	if err != nil {
		return nil, err
	}
	cacheKey := string(hashBytes([]byte(cvNetworkAuthV2Domain+"/seal-cache"), digest))
	a.cacheMu.Lock()
	if cached := a.sealed[cacheKey]; cached != nil {
		wire := append([]byte(nil), cached...)
		a.cacheMu.Unlock()
		return wire, nil
	}
	a.cacheMu.Unlock()
	algorithm := cvNetworkAuthV2OldAlgorithm
	var signature []byte
	if cvV2ReceiverOriginatedTag(tag) {
		algorithm = cvNetworkAuthV2NewAlgorithm
		secret, ok := a.receiverLocalSecrets[from]
		if !ok {
			return nil, fmt.Errorf("CV V2 receiver %d has no local identity secret", from)
		}
		signature = ed25519.Sign(secret, digest)
	} else {
		secret, ok := a.oldLocalSecrets[from]
		if !ok {
			return nil, fmt.Errorf("CV V2 old member %d has no local identity secret", from)
		}
		signature, err = cvSignValidatorV2(secret, cvNetworkAuthV2OldBLSDomain, digest)
		if err != nil {
			return nil, err
		}
	}
	wire := make([]byte, cvNetworkAuthV2HeaderBytes+len(envelope)+len(signature))
	wire[0] = cvNetworkAuthV2Version
	wire[1] = algorithm
	binary.BigEndian.PutUint32(wire[2:6], uint32(len(envelope)))
	copy(wire[6:], envelope)
	copy(wire[6+len(envelope):], signature)
	a.cacheMu.Lock()
	if len(a.sealed) >= cvNetworkAuthV2CacheLimit {
		a.sealed = make(map[string][]byte)
	}
	a.sealed[cacheKey] = append([]byte(nil), wire...)
	a.cacheMu.Unlock()
	return wire, nil
}

func (a *cvNetworkAuthenticatorV2) open(from, to int, tag string, wire []byte) ([]byte, error) {
	if a == nil || len(wire) < cvNetworkAuthV2HeaderBytes || wire[0] != cvNetworkAuthV2Version {
		return nil, fmt.Errorf("missing or invalid CV V2 network authentication")
	}
	envelopeBytes := int(binary.BigEndian.Uint32(wire[2:6]))
	if envelopeBytes <= 0 || envelopeBytes > len(wire)-cvNetworkAuthV2HeaderBytes {
		return nil, fmt.Errorf("invalid CV V2 network authentication framing")
	}
	envelope := wire[6 : 6+envelopeBytes]
	signature := wire[6+envelopeBytes:]
	digest, err := cvNetworkAuthDigestV2(a.sid, a.epoch, from, to, tag, envelope)
	if err != nil {
		return nil, err
	}
	cacheKey := string(hashBytes(
		[]byte(cvNetworkAuthV2Domain+"/open-cache"), digest, wire[1:2], signature,
	))
	a.cacheMu.Lock()
	_, cached := a.opened[cacheKey]
	a.cacheMu.Unlock()
	if cached {
		return append([]byte(nil), envelope...), nil
	}
	if cvV2ReceiverOriginatedTag(tag) {
		publicKey, ok := a.receiverPublicKeys[from]
		if !ok || wire[1] != cvNetworkAuthV2NewAlgorithm || len(signature) != ed25519.SignatureSize ||
			!ed25519.Verify(publicKey, digest, signature) {
			return nil, fmt.Errorf("invalid CV V2 receiver network signature")
		}
	} else {
		publicKey, ok := a.oldPublicKeys[from]
		if !ok || wire[1] != cvNetworkAuthV2OldAlgorithm ||
			!cvVerifyValidatorSignatureV2(&publicKey, cvNetworkAuthV2OldBLSDomain, digest, signature) {
			return nil, fmt.Errorf("invalid CV V2 old-member network signature")
		}
	}
	a.cacheMu.Lock()
	if len(a.opened) >= cvNetworkAuthV2CacheLimit {
		a.opened = make(map[string]struct{})
	}
	a.opened[cacheKey] = struct{}{}
	a.cacheMu.Unlock()
	return append([]byte(nil), envelope...), nil
}

func cvNetworkAuthDigestV2(sid string, epoch uint64, from, to int, tag string, envelope []byte) ([]byte, error) {
	if sid == "" || epoch == 0 || from < 0 || to < 0 || tag == "" || len(tag) > tcpMessageMaxTagBytes || len(envelope) == 0 {
		return nil, fmt.Errorf("invalid CV V2 network authentication statement")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(sid))
	cvWriteUint64(&wire, epoch)
	cvWriteUint64(&wire, uint64(from))
	cvWriteUint64(&wire, uint64(to))
	_ = cvWriteBytes(&wire, []byte(tag))
	_ = cvWriteBytes(&wire, envelope)
	return hashBytes([]byte(cvNetworkAuthV2Domain), wire.Bytes()), nil
}

func cvV2ReceiverOriginatedTag(tag string) bool {
	switch tag {
	case apvssTagLaneACK, cvTagLaneACKV2, cvTagAggregateRecoverGetV2, cvTagAggregateRecoverCancelV2,
		cvTagAggregatePayloadGetV2, cvTagAggregateShareV2:
		return true
	default:
		return false
	}
}
