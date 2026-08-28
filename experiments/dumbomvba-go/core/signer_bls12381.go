package core

import (
	"crypto/cipher"
	"fmt"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var _, _, g1Aff, g2Aff = bls12381.Generators()

// ── BLS12-381 Threshold Signer ─────────────────────────────────────────────

type blsSigner struct {
	id, n, threshold int
	share            fr.Element
	pubKey           bls12381.G2Affine   // group PK = sk * G2
	pubKeyShares     []bls12381.G2Affine // individual pk_i = share_i * G2
}

func NewBLS12381Signer(id int, share fr.Element, pubKey bls12381.G2Affine, pubKeyShares []bls12381.G2Affine, n, threshold int) *blsSigner {
	return &blsSigner{id: id, n: n, threshold: threshold, share: share, pubKey: pubKey, pubKeyShares: pubKeyShares}
}

func (s *blsSigner) ID() int                     { return s.id }
func (s *blsSigner) Threshold(domain string) int { return s.threshold }

// Sign produces a BLS signature share: sig_i = share_i * H(m) in G1.
func (s *blsSigner) Sign(domain string, digest []byte) ([]byte, error) {
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil { return nil, err }
	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&h, s.share.BigInt(new(big.Int)))
	return sig.Marshal(), nil
}

// Verify checks e(sig_i, G2) == e(H(m), pk_i) using the individual public key.
func (s *blsSigner) Verify(from int, domain string, digest, sigBytes []byte) bool {
	if from < 0 || from >= len(s.pubKeyShares) { return false }
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil { return false }
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil { return false }
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKeyShares[from])
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{g2Aff, negPK},
	)
	return ok
}

// Recover reconstructs the full BLS signature from threshold shares via
// Lagrange interpolation over G1.
func (s *blsSigner) Recover(domain string, digest []byte, shares map[int][]byte) ([]byte, error) {
	if len(shares) < s.threshold { return nil, fmt.Errorf("need %d got %d", s.threshold, len(shares)) }
	ids := make([]int, 0, len(shares))
	for id := range shares { ids = append(ids, id) }
	sort.Ints(ids)

	// Lagrange coefficients
	coeffs := make([]fr.Element, len(ids))
	for i, id1 := range ids {
		coeffs[i].SetOne()
		for _, id2 := range ids {
			if id1 == id2 { continue }
			// coeff *= id2 / (id2 - id1) using indices 1..n
			num := new(big.Int).SetInt64(int64(id2 + 1))
			den := new(big.Int).SetInt64(int64(id2 - id1))
			var nf, df fr.Element
			nf.SetBigInt(num); df.SetBigInt(den); df.Inverse(&df)
			nf.Mul(&nf, &df); coeffs[i].Mul(&coeffs[i], &nf)
		}
	}

	// Weighted sum of shares in G1
	var recovered bls12381.G1Affine
	zero := big.NewInt(0)
	recovered.ScalarMultiplication(&g1Aff, zero)
	for i, id := range ids {
		var sig bls12381.G1Affine
		if err := sig.Unmarshal(shares[id]); err != nil { return nil, err }
		var term bls12381.G1Affine
		term.ScalarMultiplication(&sig, coeffs[i].BigInt(new(big.Int)))
		recovered.Add(&recovered, &term)
	}
	return recovered.Marshal(), nil
}

// VerifyRecovered checks e(sig, G2) == e(H(m), PK).
func (s *blsSigner) VerifyRecovered(domain string, digest, sigBytes []byte) bool {
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil { return false }
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil { return false }
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKey)
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{g2Aff, negPK},
	)
	return ok
}

// ── Key Generation ─────────────────────────────────────────────────────────

// GenerateBLS12381TBLSBundle creates deterministic BLS12-381 threshold keys.
func GenerateBLS12381TBLSBundle(n, f int, stream cipher.Stream) ([]fr.Element, []bls12381.G2Affine, bls12381.G2Affine, int, error) {
	if n <= 0 || f < 0 || n < 3*f+1 { return nil, nil, bls12381.G2Affine{}, 0, fmt.Errorf("invalid") }
	threshold := f + 1; if threshold > n { threshold = n }
	coeffs := make([]fr.Element, threshold)
	for i := 0; i < threshold; i++ {
		buf := make([]byte, fr.Bytes)
		if stream != nil { stream.XORKeyStream(buf, buf) }
		coeffs[i].SetBytes(buf[:fr.Bytes])
	}
	shares := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var x fr.Element; x.SetInt64(int64(i + 1)); shares[i].SetZero()
		xPow := new(fr.Element); xPow.SetOne()
		for j := 0; j < threshold; j++ {
			var term fr.Element; term.Mul(&coeffs[j], xPow)
			shares[i].Add(&shares[i], &term); xPow.Mul(xPow, &x)
		}
	}
	// Individual public key shares
	pkShares := make([]bls12381.G2Affine, n)
	for i := 0; i < n; i++ { pkShares[i].ScalarMultiplication(&g2Aff, shares[i].BigInt(new(big.Int))) }
	// Group public key
	var groupPub bls12381.G2Affine
	groupPub.ScalarMultiplication(&g2Aff, coeffs[0].BigInt(new(big.Int)))
	return shares, pkShares, groupPub, threshold, nil
}
