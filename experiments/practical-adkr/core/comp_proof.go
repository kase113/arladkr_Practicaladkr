package core

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

func practicalPoint(curve elliptic.Curve, raw []byte) (*big.Int, *big.Int, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	x, y := elliptic.UnmarshalCompressed(curve, raw)
	if x == nil {
		return nil, nil, errors.New("invalid compressed curve point")
	}
	return x, y, nil
}

func practicalMarshalPoint(curve elliptic.Curve, x, y *big.Int) []byte {
	if x == nil || y == nil {
		return nil
	}
	return elliptic.MarshalCompressed(curve, x, y)
}

func practicalPointAdd(curve elliptic.Curve, left, right []byte) ([]byte, error) {
	lx, ly, err := practicalPoint(curve, left)
	if err != nil {
		return nil, err
	}
	rx, ry, err := practicalPoint(curve, right)
	if err != nil {
		return nil, err
	}
	if lx == nil {
		return append([]byte(nil), right...), nil
	}
	if rx == nil {
		return append([]byte(nil), left...), nil
	}
	x, y := curve.Add(lx, ly, rx, ry)
	return practicalMarshalPoint(curve, x, y), nil
}

func practicalPointSub(curve elliptic.Curve, left, right []byte) ([]byte, error) {
	rx, ry, err := practicalPoint(curve, right)
	if err != nil {
		return nil, err
	}
	if rx == nil {
		return append([]byte(nil), left...), nil
	}
	negY := new(big.Int).Neg(ry)
	negY.Mod(negY, curve.Params().P)
	return practicalPointAdd(curve, left, elliptic.MarshalCompressed(curve, rx, negY))
}

func practicalPointScalar(curve elliptic.Curve, point []byte, scalar *big.Int) ([]byte, error) {
	px, py, err := practicalPoint(curve, point)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).Mod(new(big.Int).Set(scalar), curve.Params().N)
	if px == nil || s.Sign() == 0 {
		return nil, nil
	}
	x, y := curve.ScalarMult(px, py, s.Bytes())
	return practicalMarshalPoint(curve, x, y), nil
}

func practicalBasePoint(curve elliptic.Curve, scalar *big.Int) []byte {
	s := new(big.Int).Mod(new(big.Int).Set(scalar), curve.Params().N)
	if s.Sign() == 0 {
		return nil
	}
	x, y := curve.ScalarBaseMult(s.Bytes())
	return practicalMarshalPoint(curve, x, y)
}

func practicalHPoint(curve elliptic.Curve, scalar *big.Int) []byte {
	s := new(big.Int).Mod(new(big.Int).Set(scalar), curve.Params().N)
	if s.Sign() == 0 {
		return nil
	}
	hx, hy := hashToPoint(curve)
	x, y := curve.ScalarMult(hx, hy, s.Bytes())
	return practicalMarshalPoint(curve, x, y)
}

func encryptDXTBlinding(
	curve elliptic.Curve,
	public []byte,
	blinding *big.Int,
) (DXTBlindingCiphertext, *big.Int, error) {
	pubX, pubY, err := practicalPoint(curve, public)
	if err != nil || pubX == nil || blinding == nil {
		return DXTBlindingCiphertext{}, nil, errors.New("invalid DXT blinding encryption input")
	}
	var randomness *big.Int
	for randomness == nil || randomness.Sign() == 0 {
		randomness, err = rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			return DXTBlindingCiphertext{}, nil, err
		}
	}
	c0 := practicalBasePoint(curve, randomness)
	sharedX, sharedY := curve.ScalarMult(pubX, pubY, randomness.Bytes())
	c1, err := practicalPointAdd(curve, practicalMarshalPoint(curve, sharedX, sharedY), practicalHPoint(curve, blinding))
	if err != nil {
		return DXTBlindingCiphertext{}, nil, err
	}
	return DXTBlindingCiphertext{C0: c0, C1: c1}, randomness, nil
}

func decryptDXTBlinding(
	curve elliptic.Curve,
	private *big.Int,
	ciphertext DXTBlindingCiphertext,
) ([]byte, error) {
	if private == nil || private.Sign() <= 0 || private.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("invalid CompProve private key")
	}
	shared, err := practicalPointScalar(curve, ciphertext.C0, private)
	if err != nil {
		return nil, err
	}
	return practicalPointSub(curve, ciphertext.C1, shared)
}

func compDLogChallenge(curve elliptic.Curve, binding, generator, statement, commitment []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-DLOG-v1"))
	writeDXTHashField(h, binding)
	writeDXTHashField(h, generator)
	writeDXTHashField(h, statement)
	writeDXTHashField(h, commitment)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, curve.Params().N)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

func proveCompDLog(curve elliptic.Curve, witness *big.Int, generator, statement, binding []byte) (NIZKProof, error) {
	w := new(big.Int).Mod(new(big.Int).Set(witness), curve.Params().N)
	if w.Sign() == 0 {
		if len(statement) != 0 {
			return NIZKProof{}, errors.New("zero witness has non-identity statement")
		}
		return NIZKProof{}, nil
	}
	if len(generator) == 0 || len(statement) == 0 {
		return NIZKProof{}, errors.New("nonzero DLog witness has identity statement")
	}
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return NIZKProof{}, err
	}
	commitment, err := practicalPointScalar(curve, generator, k)
	if err != nil {
		return NIZKProof{}, err
	}
	e := compDLogChallenge(curve, binding, generator, statement, commitment)
	response := new(big.Int).Mul(e, w)
	response.Sub(k, response).Mod(response, curve.Params().N)
	return NIZKProof{Challenge: e.Bytes(), Response: response.Bytes()}, nil
}

func verifyCompDLog(curve elliptic.Curve, generator, statement, binding []byte, proof NIZKProof) bool {
	if len(statement) == 0 {
		return len(proof.Challenge) == 0 && len(proof.Response) == 0
	}
	if len(generator) == 0 || len(proof.Challenge) == 0 {
		return false
	}
	e := new(big.Int).SetBytes(proof.Challenge)
	if e.Sign() <= 0 || e.Cmp(curve.Params().N) >= 0 {
		return false
	}
	s := new(big.Int).SetBytes(proof.Response)
	if s.Cmp(curve.Params().N) >= 0 {
		return false
	}
	gs, err := practicalPointScalar(curve, generator, s)
	if err != nil {
		return false
	}
	ye, err := practicalPointScalar(curve, statement, e)
	if err != nil {
		return false
	}
	commitment, err := practicalPointAdd(curve, gs, ye)
	if err != nil {
		return false
	}
	want := compDLogChallenge(curve, binding, generator, statement, commitment)
	return want.Cmp(e) == 0
}

func compDHChallenge(curve elliptic.Curve, binding, g, x, public, y, t1, t2 []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-DH-v1"))
	for _, field := range [][]byte{binding, g, x, public, y, t1, t2} {
		writeDXTHashField(h, field)
	}
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, curve.Params().N)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

func proveCompDH(curve elliptic.Curve, private *big.Int, g, x, public, y, binding []byte) (NIZKProof, error) {
	if len(x) == 0 {
		if len(y) != 0 {
			return NIZKProof{}, errors.New("identity DH base has non-identity image")
		}
		return NIZKProof{}, nil
	}
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return NIZKProof{}, err
	}
	t1, err := practicalPointScalar(curve, g, k)
	if err != nil {
		return NIZKProof{}, err
	}
	t2, err := practicalPointScalar(curve, x, k)
	if err != nil {
		return NIZKProof{}, err
	}
	e := compDHChallenge(curve, binding, g, x, public, y, t1, t2)
	response := new(big.Int).Mul(e, private)
	response.Sub(k, response).Mod(response, curve.Params().N)
	return NIZKProof{Challenge: packDHTupleChallenge(e, t1, t2), Response: response.Bytes()}, nil
}

func verifyCompDH(curve elliptic.Curve, g, x, public, y, binding []byte, proof NIZKProof) bool {
	if len(x) == 0 {
		return len(y) == 0 && len(proof.Challenge) == 0 && len(proof.Response) == 0
	}
	e, t1, t2 := unpackDHTupleChallenge(proof.Challenge)
	if e == nil || e.Sign() <= 0 || e.Cmp(curve.Params().N) >= 0 {
		return false
	}
	s := new(big.Int).SetBytes(proof.Response)
	if s.Cmp(curve.Params().N) >= 0 {
		return false
	}
	gs, err := practicalPointScalar(curve, g, s)
	if err != nil {
		return false
	}
	publicE, err := practicalPointScalar(curve, public, e)
	if err != nil {
		return false
	}
	reT1, err := practicalPointAdd(curve, gs, publicE)
	if err != nil || !bytes.Equal(t1, reT1) {
		return false
	}
	xs, err := practicalPointScalar(curve, x, s)
	if err != nil {
		return false
	}
	ye, err := practicalPointScalar(curve, y, e)
	if err != nil {
		return false
	}
	reT2, err := practicalPointAdd(curve, xs, ye)
	if err != nil || !bytes.Equal(t2, reT2) {
		return false
	}
	want := compDHChallenge(curve, binding, g, x, public, y, reT1, reT2)
	return want.Cmp(e) == 0
}

func compSelectedDigest(selected []int, transcripts map[int]*DXTTranscript) ([]byte, []int, error) {
	canonical := append([]int(nil), selected...)
	sort.Ints(canonical)
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-TRANSCRIPTS-v1"))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(len(canonical)))
	h.Write(number[:])
	for i, dealer := range canonical {
		if i > 0 && canonical[i-1] == dealer {
			return nil, nil, fmt.Errorf("duplicate selected dealer %d", dealer)
		}
		transcript := transcripts[dealer]
		if transcript == nil || transcript.Dealer != dealer {
			return nil, nil, fmt.Errorf("missing selected transcript %d", dealer)
		}
		raw, err := json.Marshal(transcript)
		if err != nil {
			return nil, nil, err
		}
		digest := sha256.Sum256(raw)
		binary.BigEndian.PutUint64(number[:], uint64(dealer))
		h.Write(number[:])
		writeDXTHashField(h, digest[:])
	}
	return h.Sum(nil), canonical, nil
}

func compProofBinding(sid string, epoch uint64, nodeID int, selectedDigest, aggregateCommitment, public []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-COMP-PROOF-BINDING-v1"))
	writeDXTHashField(h, []byte(sid))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], epoch)
	h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(nodeID))
	h.Write(number[:])
	for _, field := range [][]byte{selectedDigest, aggregateCommitment, public} {
		writeDXTHashField(h, field)
	}
	return h.Sum(nil)
}

func compAggregateStatement(
	curve elliptic.Curve,
	nodeID int,
	selected []int,
	transcripts map[int]*DXTTranscript,
) (aggregate, x, c1Product []byte, ackCount, veCount int, err error) {
	for _, dealer := range selected {
		transcript := transcripts[dealer]
		if transcript == nil {
			err = fmt.Errorf("missing transcript %d", dealer)
			return
		}
		aggregate, err = practicalPointAdd(curve, aggregate, transcript.Commitments[nodeID])
		if err != nil {
			return
		}
		if _, ok := transcript.Signatures[nodeID]; ok {
			ackCount++
			continue
		}
		ciphertext, ok := transcript.BlindingCiphertexts[nodeID]
		if !ok {
			err = fmt.Errorf("transcript %d lacks receiver %d blinding ciphertext", dealer, nodeID)
			return
		}
		x, err = practicalPointAdd(curve, x, ciphertext.C0)
		if err != nil {
			return
		}
		c1Product, err = practicalPointAdd(curve, c1Product, ciphertext.C1)
		if err != nil {
			return
		}
		veCount++
	}
	return
}

func compProve(
	sid string,
	epoch uint64,
	nodeID int,
	selected []int,
	selectedDigest []byte,
	transcripts map[int]*DXTTranscript,
	localShares map[int]map[int]SharePair,
	paillierPrivate *PaillierPrivateKey,
	compPrivate *big.Int,
	compPublic []byte,
) (CompPublicKeyShare, *big.Int, error) {
	curve := elliptic.P256()
	order := curve.Params().N
	aggregate, x, c1Product, _, _, err := compAggregateStatement(curve, nodeID, selected, transcripts)
	if err != nil {
		return CompPublicKeyShare{}, nil, err
	}
	z := new(big.Int)
	ackRandomness := new(big.Int)
	var decryptedBlinding []byte
	for _, dealer := range selected {
		transcript := transcripts[dealer]
		if _, acked := transcript.Signatures[nodeID]; acked {
			share, ok := localShares[dealer][nodeID]
			if !ok || share.S == nil || share.SR == nil {
				return CompPublicKeyShare{}, nil, fmt.Errorf("receiver %d lacks valid ACK aux for dealer %d (missing entry)", nodeID, dealer)
			}
			if !bytes.Equal(commitSharePair(curve, share.S, share.SR), transcript.Commitments[nodeID]) {
				return CompPublicKeyShare{}, nil, fmt.Errorf("receiver %d lacks valid ACK aux for dealer %d (commitment mismatch)", nodeID, dealer)
			}
			z.Add(z, share.S).Mod(z, order)
			ackRandomness.Add(ackRandomness, share.SR).Mod(ackRandomness, order)
			continue
		}
		if paillierPrivate == nil {
			return CompPublicKeyShare{}, nil, fmt.Errorf("receiver %d lacks Paillier private key", nodeID)
		}
		ciphertext := new(big.Int).SetBytes(transcript.Ciphertexts[nodeID])
		share, decryptErr := paillierPrivate.Decrypt(ciphertext)
		if decryptErr != nil {
			return CompPublicKeyShare{}, nil, fmt.Errorf("decrypt receiver %d dealer %d share: %w", nodeID, dealer, decryptErr)
		}
		z.Add(z, share).Mod(z, order)
		blinding, decryptErr := decryptDXTBlinding(curve, compPrivate, transcript.BlindingCiphertexts[nodeID])
		if decryptErr != nil {
			return CompPublicKeyShare{}, nil, decryptErr
		}
		decryptedBlinding, err = practicalPointAdd(curve, decryptedBlinding, blinding)
		if err != nil {
			return CompPublicKeyShare{}, nil, err
		}
	}
	pkShare := practicalBasePoint(curve, z)
	ackBlinding := practicalHPoint(curve, ackRandomness)
	y, err := practicalPointSub(curve, c1Product, decryptedBlinding)
	if err != nil {
		return CompPublicKeyShare{}, nil, err
	}
	relation, err := practicalPointAdd(curve, pkShare, ackBlinding)
	if err == nil {
		relation, err = practicalPointAdd(curve, relation, decryptedBlinding)
	}
	if err != nil || !bytes.Equal(relation, aggregate) {
		return CompPublicKeyShare{}, nil, errors.New("CompProve aggregate commitment relation failed")
	}
	binding := compProofBinding(sid, epoch, nodeID, selectedDigest, aggregate, compPublic)
	g := practicalBasePoint(curve, big.NewInt(1))
	hx, hy := hashToPoint(curve)
	h := elliptic.MarshalCompressed(curve, hx, hy)
	secretProof, err := proveCompDLog(curve, z, g, pkShare, binding)
	if err != nil {
		return CompPublicKeyShare{}, nil, err
	}
	ackProof, err := proveCompDLog(curve, ackRandomness, h, ackBlinding, binding)
	if err != nil {
		return CompPublicKeyShare{}, nil, err
	}
	dhProof, err := proveCompDH(curve, compPrivate, g, x, compPublic, y, binding)
	if err != nil {
		return CompPublicKeyShare{}, nil, err
	}
	return CompPublicKeyShare{
		NodeID:  nodeID,
		PKShare: pkShare,
		Proof: CompProof{
			AckBlinding: ackBlinding,
			Y:           y,
			Secret:      secretProof,
			AckOpening:  ackProof,
			DH:          dhProof,
		},
	}, z, nil
}

func verifyCompPublicKeyShare(
	sid string,
	epoch uint64,
	share CompPublicKeyShare,
	selected []int,
	selectedDigest []byte,
	transcripts map[int]*DXTTranscript,
	compPublic []byte,
) bool {
	curve := elliptic.P256()
	aggregate, x, c1Product, _, _, err := compAggregateStatement(curve, share.NodeID, selected, transcripts)
	if err != nil {
		return false
	}
	decryptedBlinding, err := practicalPointSub(curve, c1Product, share.Proof.Y)
	if err != nil {
		return false
	}
	relation, err := practicalPointAdd(curve, share.PKShare, share.Proof.AckBlinding)
	if err == nil {
		relation, err = practicalPointAdd(curve, relation, decryptedBlinding)
	}
	if err != nil || !bytes.Equal(relation, aggregate) {
		return false
	}
	binding := compProofBinding(sid, epoch, share.NodeID, selectedDigest, aggregate, compPublic)
	g := practicalBasePoint(curve, big.NewInt(1))
	hx, hy := hashToPoint(curve)
	h := elliptic.MarshalCompressed(curve, hx, hy)
	return verifyCompDLog(curve, g, share.PKShare, binding, share.Proof.Secret) &&
		verifyCompDLog(curve, h, share.Proof.AckBlinding, binding, share.Proof.AckOpening) &&
		verifyCompDH(curve, g, x, compPublic, share.Proof.Y, binding, share.Proof.DH)
}

func interpolateCompPublicKeys(
	committee []int,
	shares map[int]CompPublicKeyShare,
	threshold int,
) ([]byte, map[int][]byte, error) {
	if threshold <= 0 || len(shares) < threshold {
		return nil, nil, fmt.Errorf("not enough CompProve shares: have=%d need=%d", len(shares), threshold)
	}
	ids := make([]int, 0, len(shares))
	committeeSet := make(map[int]struct{}, len(committee))
	for _, id := range committee {
		committeeSet[id] = struct{}{}
	}
	for id := range shares {
		if _, ok := committeeSet[id]; !ok {
			return nil, nil, fmt.Errorf("CompProve share from non-committee node %d", id)
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	ids = ids[:threshold]
	curve := elliptic.P256()
	points := make([]*big.Int, len(ids))
	for i, id := range ids {
		points[i] = big.NewInt(int64(id + 1))
		if _, _, err := practicalPoint(curve, shares[id].PKShare); err != nil {
			return nil, nil, err
		}
	}
	interpolateAt := func(target *big.Int) ([]byte, error) {
		var result []byte
		for i, id := range ids {
			lambda := lagrangeCoefficientAt(points, i, target, curve.Params().N)
			if lambda == nil {
				return nil, errors.New("invalid CompProve interpolation points")
			}
			term, err := practicalPointScalar(curve, shares[id].PKShare, lambda)
			if err != nil {
				return nil, err
			}
			result, err = practicalPointAdd(curve, result, term)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	}
	group, err := interpolateAt(big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	all := make(map[int][]byte, len(committee))
	for _, id := range committee {
		value, interpErr := interpolateAt(big.NewInt(int64(id + 1)))
		if interpErr != nil {
			return nil, nil, interpErr
		}
		all[id] = value
	}
	return group, all, nil
}
