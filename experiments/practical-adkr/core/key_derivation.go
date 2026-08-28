// key_derivation.go — NIZK 证明 + Lagrange 插值恢复门限公钥
// 对应论文 Algorithm 3: Public Key Derivation
package core

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// --- NIZK: Proof of Knowledge of Discrete Log ---
// Proves knowledge of x such that Y = g^x (Schnorr protocol, Fiat-Shamir)

// ProveNIZKDLog generates a NIZK proof that prover knows x s.t. Y = g^x.
func ProveNIZKDLog(curve elliptic.Curve, x *big.Int, Y []byte) (*NIZKProof, error) {
	order := curve.Params().N

	// Random commitment: k ← Z_q, T = g^k
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	tx, ty := curve.ScalarBaseMult(k.Bytes())
	tBytes := elliptic.MarshalCompressed(curve, tx, ty)

	// Challenge: e = H(g, Y, T)
	e := nizkDLogChallenge(curve, Y, tBytes)

	// Response: s = k - e*x mod q
	s := new(big.Int).Mul(e, x)
	s.Sub(k, s)
	s.Mod(s, order)

	return &NIZKProof{
		Challenge: e.Bytes(),
		Response:  s.Bytes(),
	}, nil
}

// VerifyNIZKDLog verifies a NIZK proof of discrete log.
// Checks: g^s * Y^e == T (reconstructed from challenge)
func VerifyNIZKDLog(curve elliptic.Curve, Y []byte, proof *NIZKProof) bool {
	if proof == nil || len(Y) == 0 {
		return false
	}

	yx, yy := elliptic.UnmarshalCompressed(curve, Y)
	if yx == nil {
		return false
	}

	order := curve.Params().N
	e := new(big.Int).SetBytes(proof.Challenge)
	s := new(big.Int).SetBytes(proof.Response)

	// Reconstruct T = g^s * Y^e
	gsx, gsy := curve.ScalarBaseMult(new(big.Int).Mod(s, order).Bytes())
	yex, yey := curve.ScalarMult(yx, yy, new(big.Int).Mod(e, order).Bytes())
	reconstructedTx, reconstructedTy := curve.Add(gsx, gsy, yex, yey)
	tBytes := elliptic.MarshalCompressed(curve, reconstructedTx, reconstructedTy)

	// Recompute challenge
	eCheck := nizkDLogChallenge(curve, Y, tBytes)
	return e.Cmp(eCheck) == 0
}

func nizkDLogChallenge(curve elliptic.Curve, Y, T []byte) *big.Int {
	order := curve.Params().N
	// Generator bytes
	gx, gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	gBytes := elliptic.MarshalCompressed(curve, gx, gy)

	h := sha256.New()
	h.Write([]byte("PADKR-NIZK-DLOG"))
	h.Write(gBytes)
	h.Write(Y)
	h.Write(T)
	digest := h.Sum(nil)

	e := new(big.Int).SetBytes(digest)
	e.Mod(e, order)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

// --- NIZK: Proof of DH Tuple ---
// Proves (g, h, u, v) is a DH tuple: ∃ x s.t. u = g^x AND v = h^x

// ProveNIZKDHTuple generates a NIZK proof for a DH tuple.
func ProveNIZKDHTuple(curve elliptic.Curve, x *big.Int,
	gBytes, hBytes, uBytes, vBytes []byte) (*NIZKProof, error) {

	order := curve.Params().N

	gx, gy := elliptic.UnmarshalCompressed(curve, gBytes)
	hx, hy := elliptic.UnmarshalCompressed(curve, hBytes)
	if gx == nil || hx == nil {
		return nil, errors.New("invalid base points")
	}

	// Random k
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}

	// T1 = g^k, T2 = h^k
	t1x, t1y := curve.ScalarMult(gx, gy, k.Bytes())
	t2x, t2y := curve.ScalarMult(hx, hy, k.Bytes())
	t1Bytes := elliptic.MarshalCompressed(curve, t1x, t1y)
	t2Bytes := elliptic.MarshalCompressed(curve, t2x, t2y)

	// Challenge
	e := nizkDHTupleChallenge(gBytes, hBytes, uBytes, vBytes, t1Bytes, t2Bytes, order)

	// Response s = k - e*x mod q
	s := new(big.Int).Mul(e, x)
	s.Sub(k, s)
	s.Mod(s, order)

	// Pack T1, T2 into Challenge field for verification
	challenge := packDHTupleChallenge(e, t1Bytes, t2Bytes)

	return &NIZKProof{
		Challenge: challenge,
		Response:  s.Bytes(),
	}, nil
}

// VerifyNIZKDHTuple verifies a NIZK proof for a DH tuple.
func VerifyNIZKDHTuple(curve elliptic.Curve,
	gBytes, hBytes, uBytes, vBytes []byte, proof *NIZKProof) bool {

	if proof == nil {
		return false
	}

	gx, gy := elliptic.UnmarshalCompressed(curve, gBytes)
	hx, hy := elliptic.UnmarshalCompressed(curve, hBytes)
	ux, uy := elliptic.UnmarshalCompressed(curve, uBytes)
	vx, vy := elliptic.UnmarshalCompressed(curve, vBytes)
	if gx == nil || hx == nil || ux == nil || vx == nil {
		return false
	}

	order := curve.Params().N
	e, t1Bytes, t2Bytes := unpackDHTupleChallenge(proof.Challenge)
	if e == nil {
		return false
	}
	s := new(big.Int).SetBytes(proof.Response)
	sMod := new(big.Int).Mod(s, order)
	eMod := new(big.Int).Mod(e, order)

	// Verify T1 == g^s * u^e
	gsx, gsy := curve.ScalarMult(gx, gy, sMod.Bytes())
	uex, uey := curve.ScalarMult(ux, uy, eMod.Bytes())
	reT1x, reT1y := curve.Add(gsx, gsy, uex, uey)
	reT1 := elliptic.MarshalCompressed(curve, reT1x, reT1y)

	// Verify T2 == h^s * v^e
	hsx, hsy := curve.ScalarMult(hx, hy, sMod.Bytes())
	vex, vey := curve.ScalarMult(vx, vy, eMod.Bytes())
	reT2x, reT2y := curve.Add(hsx, hsy, vex, vey)
	reT2 := elliptic.MarshalCompressed(curve, reT2x, reT2y)

	// Recompute challenge
	eCheck := nizkDHTupleChallenge(gBytes, hBytes, uBytes, vBytes, reT1, reT2, order)
	return e.Cmp(eCheck) == 0 && equalCommit(t1Bytes, reT1) && equalCommit(t2Bytes, reT2)
}

func nizkDHTupleChallenge(g, h, u, v, t1, t2 []byte, order *big.Int) *big.Int {
	dig := sha256.New()
	dig.Write([]byte("PADKR-NIZK-DH-TUPLE"))
	dig.Write(g)
	dig.Write(h)
	dig.Write(u)
	dig.Write(v)
	dig.Write(t1)
	dig.Write(t2)
	out := dig.Sum(nil)
	e := new(big.Int).SetBytes(out)
	e.Mod(e, order)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

func packDHTupleChallenge(e *big.Int, t1, t2 []byte) []byte {
	eBytes := e.Bytes()
	// Format: [1 byte len(eBytes)] [eBytes] [1 byte len(t1)] [t1] [t2]
	out := make([]byte, 0, 2+len(eBytes)+len(t1)+len(t2))
	out = append(out, byte(len(eBytes)))
	out = append(out, eBytes...)
	out = append(out, byte(len(t1)))
	out = append(out, t1...)
	out = append(out, t2...)
	return out
}

func unpackDHTupleChallenge(data []byte) (*big.Int, []byte, []byte) {
	if len(data) < 3 {
		return nil, nil, nil
	}
	eLen := int(data[0])
	if len(data) < 1+eLen+1 {
		return nil, nil, nil
	}
	e := new(big.Int).SetBytes(data[1 : 1+eLen])
	rest := data[1+eLen:]
	t1Len := int(rest[0])
	if len(rest) < 1+t1Len {
		return nil, nil, nil
	}
	t1 := rest[1 : 1+t1Len]
	t2 := rest[1+t1Len:]
	return e, t1, t2
}

// --- Lagrange Interpolation for Threshold Public Key ---

// LagrangeCoefficient computes λ_i(0) = ∏_{j≠i} (0-x_j)/(x_i-x_j) mod q
// where x_i = evalPoints[i] and we evaluate at x=0.
func LagrangeCoefficient(evalPoints []*big.Int, i int, mod *big.Int) *big.Int {
	xi := evalPoints[i]
	num := big.NewInt(1)
	den := big.NewInt(1)

	for j, xj := range evalPoints {
		if j == i {
			continue
		}
		// num *= (0 - xj) = -xj
		negXj := new(big.Int).Neg(xj)
		negXj.Mod(negXj, mod)
		num.Mul(num, negXj)
		num.Mod(num, mod)

		// den *= (xi - xj)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, mod)
		den.Mul(den, diff)
		den.Mod(den, mod)
	}

	denInv := new(big.Int).ModInverse(den, mod)
	if denInv == nil {
		return big.NewInt(0)
	}
	result := new(big.Int).Mul(num, denInv)
	result.Mod(result, mod)
	return result
}

// DeriveThresholdPK derives the new threshold public key from individual
// public key shares using Lagrange interpolation in the exponent.
//
// Given shares pk_i = g^{s_i} where s_i = f(i), this computes:
// PK = ∏ pk_i^{λ_i(0)} = g^{∑ λ_i(0)*s_i} = g^{f(0)} = g^s
func DeriveThresholdPK(curve elliptic.Curve, pkShares []PublicKeyShare, threshold int) ([]byte, error) {
	if len(pkShares) < threshold {
		return nil, errors.New("not enough shares for threshold")
	}

	order := curve.Params().N
	// Use first `threshold` shares
	shares := pkShares[:threshold]

	// Evaluation points: x_i = nodeID + 1 (matching evalPoly in Deal)
	evalPoints := make([]*big.Int, len(shares))
	for i, s := range shares {
		evalPoints[i] = big.NewInt(int64(s.NodeID + 1))
	}

	// Start with point at infinity (identity)
	var resultX, resultY *big.Int
	first := true

	for i, s := range shares {
		// Verify NIZK proof
		if !VerifyNIZKDLog(curve, s.PKShare, &s.Proof) {
			return nil, errors.New("NIZK proof verification failed for share")
		}

		lambda := LagrangeCoefficient(evalPoints, i, order)

		px, py := elliptic.UnmarshalCompressed(curve, s.PKShare)
		if px == nil {
			return nil, errors.New("invalid public key share")
		}

		// pk_i^{λ_i}
		lx, ly := curve.ScalarMult(px, py, lambda.Bytes())

		if first {
			resultX, resultY = lx, ly
			first = false
		} else {
			resultX, resultY = curve.Add(resultX, resultY, lx, ly)
		}
	}

	if resultX == nil {
		return nil, errors.New("failed to derive threshold PK")
	}
	return elliptic.MarshalCompressed(curve, resultX, resultY), nil
}

// GeneratePKShareWithProof generates a public key share and its NIZK proof
// from a secret share.
func GeneratePKShareWithProof(curve elliptic.Curve, nodeID int, secretShare *big.Int) (*PublicKeyShare, error) {
	order := curve.Params().N
	sMod := new(big.Int).Mod(secretShare, order)

	pkX, pkY := curve.ScalarBaseMult(sMod.Bytes())
	pkBytes := elliptic.MarshalCompressed(curve, pkX, pkY)

	proof, err := ProveNIZKDLog(curve, sMod, pkBytes)
	if err != nil {
		return nil, err
	}

	return &PublicKeyShare{
		NodeID:  nodeID,
		PKShare: pkBytes,
		Proof:   *proof,
	}, nil
}
