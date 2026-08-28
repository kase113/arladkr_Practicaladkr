package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

type Ed25519Signer struct {
	id   int
	priv ed25519.PrivateKey
	pubs []ed25519.PublicKey
}

func GenerateEd25519KeySet(n int) ([]ed25519.PublicKey, []ed25519.PrivateKey, error) {
	if n <= 0 {
		return nil, nil, fmt.Errorf("keyset size must be positive")
	}
	pub := make([]ed25519.PublicKey, n)
	priv := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub[i] = append(ed25519.PublicKey(nil), pk...)
		priv[i] = append(ed25519.PrivateKey(nil), sk...)
	}
	return pub, priv, nil
}

func NewEd25519Signer(id int, priv ed25519.PrivateKey, pubs []ed25519.PublicKey) (*Ed25519Signer, error) {
	if id < 0 || id >= len(pubs) {
		return nil, fmt.Errorf("%w: signer id %d out of range", ErrInvalidConfig, id)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid private key size", ErrInvalidConfig)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("%w: empty public keys", ErrInvalidConfig)
	}
	pubCopy := make([]ed25519.PublicKey, len(pubs))
	for i := range pubs {
		if len(pubs[i]) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid public key size for id %d", ErrInvalidConfig, i)
		}
		pubCopy[i] = append(ed25519.PublicKey(nil), pubs[i]...)
	}
	return &Ed25519Signer{
		id:   id,
		priv: append(ed25519.PrivateKey(nil), priv...),
		pubs: pubCopy,
	}, nil
}

func (s *Ed25519Signer) ID() int {
	return s.id
}

func (s *Ed25519Signer) Sign(domain string, digest []byte) ([]byte, error) {
	if len(s.priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("missing private key")
	}
	msg := domainDigest(domain, digest)
	sig := ed25519.Sign(s.priv, msg)
	return sig, nil
}

func (s *Ed25519Signer) Verify(from int, domain string, digest, sig []byte) bool {
	if from < 0 || from >= len(s.pubs) {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	pub := s.pubs[from]
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg := domainDigest(domain, digest)
	return ed25519.Verify(pub, msg, sig)
}

func domainDigest(domain string, digest []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(digest)
	return h.Sum(nil)
}
