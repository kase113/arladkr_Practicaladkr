// paillier.go — Paillier 同态加密（完全复用自 adkr-go）
package core

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type PaillierPublicKey struct {
	N       *big.Int
	NSquare *big.Int
	G       *big.Int
}

type PaillierPrivateKey struct {
	PublicKey *PaillierPublicKey
	Lambda    *big.Int
	Mu        *big.Int
}

var (
	bigOne  = big.NewInt(1)
	bigZero = big.NewInt(0)
)

func GeneratePaillierKey(bits int) (*PaillierPrivateKey, error) {
	if bits < 2048 {
		return nil, errors.New("paillier key size too small")
	}
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	for p.Cmp(q) == 0 {
		q, err = rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, err
		}
	}

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, bigOne)

	pm1 := new(big.Int).Sub(p, bigOne)
	qm1 := new(big.Int).Sub(q, bigOne)
	lambda := lcm(pm1, qm1)

	u := new(big.Int).Exp(g, lambda, n2)
	l := L(u, n)
	mu := new(big.Int).ModInverse(l, n)
	if mu == nil {
		return nil, errors.New("failed to invert paillier L value")
	}

	return &PaillierPrivateKey{
		PublicKey: &PaillierPublicKey{N: n, NSquare: n2, G: g},
		Lambda:    lambda,
		Mu:        mu,
	}, nil
}

func (pk *PaillierPublicKey) Encrypt(m *big.Int) (*big.Int, error) {
	if pk == nil || pk.N == nil {
		return nil, errors.New("nil paillier public key")
	}
	if m.Sign() < 0 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("plaintext out of range")
	}
	r, err := pk.RandomCoprime()
	if err != nil {
		return nil, err
	}
	return pk.EncryptWithRandom(m, r)
}

func (pk *PaillierPublicKey) EncryptWithRandom(m, r *big.Int) (*big.Int, error) {
	if pk == nil || pk.N == nil {
		return nil, errors.New("nil paillier public key")
	}
	if m.Sign() < 0 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("plaintext out of range")
	}
	if r == nil || r.Sign() <= 0 || r.Cmp(pk.N) >= 0 {
		return nil, errors.New("paillier randomness out of range")
	}
	if new(big.Int).GCD(nil, nil, r, pk.N).Cmp(bigOne) != 0 {
		return nil, errors.New("paillier randomness not coprime")
	}
	gm := new(big.Int).Exp(pk.G, m, pk.NSquare)
	rn := new(big.Int).Exp(r, pk.N, pk.NSquare)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.NSquare)
	return c, nil
}

func (pk *PaillierPublicKey) RandomCoprime() (*big.Int, error) {
	if pk == nil || pk.N == nil {
		return nil, errors.New("nil paillier public key")
	}
	return sampleCoprime(pk.N)
}

func (pk *PaillierPublicKey) Add(c1, c2 *big.Int) *big.Int {
	out := new(big.Int).Mul(c1, c2)
	out.Mod(out, pk.NSquare)
	return out
}

func (pk *PaillierPublicKey) Neutral() *big.Int {
	return big.NewInt(1)
}

func (sk *PaillierPrivateKey) Decrypt(c *big.Int) (*big.Int, error) {
	if sk == nil || sk.PublicKey == nil {
		return nil, errors.New("nil paillier private key")
	}
	if c.Sign() <= 0 || c.Cmp(sk.PublicKey.NSquare) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	u := new(big.Int).Exp(c, sk.Lambda, sk.PublicKey.NSquare)
	l := L(u, sk.PublicKey.N)
	m := new(big.Int).Mul(l, sk.Mu)
	m.Mod(m, sk.PublicKey.N)
	return m, nil
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	ab := new(big.Int).Mul(a, b)
	return ab.Div(ab, g)
}

func L(u, n *big.Int) *big.Int {
	out := new(big.Int).Sub(u, bigOne)
	return out.Div(out, n)
}

func sampleCoprime(n *big.Int) (*big.Int, error) {
	max := new(big.Int).Sub(n, bigOne)
	for i := 0; i < 128; i++ {
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		r.Add(r, bigOne)
		if new(big.Int).GCD(nil, nil, r, n).Cmp(bigOne) == 0 {
			return r, nil
		}
	}
	return nil, errors.New("failed to sample paillier randomness")
}
