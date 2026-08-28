package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvChunkProofRepetitions = 32
	cvChunkChallengeBits    = 8
	cvChunkChallengeMask    = (1 << cvChunkChallengeBits) - 1

	cvSharingBatchDomain     = "ARL-CV-sAPVSS/share-batch"
	cvSharingChallengeDomain = "ARL-CV-sAPVSS/share-challenge"
	cvChunkFirstDomain       = "ARL-CV-sAPVSS/chunk-first"
	cvChunkSecondDomain      = "ARL-CV-sAPVSS/chunk-second"
	cvChunkY0Domain          = "ARL-CV-sAPVSS/chunk-y0"
	cvExactRangeDomain       = "ARL-CV-sAPVSS/exact-range"
)

type cvSharingProof struct {
	fScalar, fBlinding         bls12381.G1Affine
	a                          bls12381.G1Affine
	yScalar, yBlinding         bls12381.G1Affine
	zScalar, zBlinding         fr.Element
	zScalarCoin, zBlindingCoin fr.Element
}

type cvBitProof struct {
	t0, t1     bls12381.G1Affine
	e0, z0, z1 fr.Element
}

type cvRangeLinkProof struct {
	tCoin        bls12381.G1Affine
	tCommitments []bls12381.G1Affine
	tCiphertexts []bls12381.G1Affine
	zCoin        fr.Element
	zDigits      []fr.Element
	zRhos        []fr.Element
}

type cvExactRangeProof struct {
	commitments []bls12381.G1Affine
	bits        []cvBitProof
	links       []cvRangeLinkProof
}

type cvChunkingProof struct {
	y0              bls12381.G1Affine
	b, c, d         []bls12381.G1Affine
	y               bls12381.G1Affine
	zCoins, zDigits []fr.Element
	zBeta           fr.Element
	exactRange      cvExactRangeProof
}

type cvLeafProof struct {
	sharing  cvSharingProof
	chunking cvChunkingProof
}

type cvChunkChallenges [][][]uint16

func cvWriteScalar(buffer *bytes.Buffer, scalar *fr.Element) {
	encoded := scalar.Bytes()
	_, _ = buffer.Write(encoded[:])
}

func cvWritePointVector(buffer *bytes.Buffer, points []bls12381.G1Affine) error {
	return cvWritePointVectorMode(buffer, points, true)
}

func cvWritePointVectorMode(buffer *bytes.Buffer, points []bls12381.G1Affine, validatePoints bool) error {
	if err := cvWriteUint32(buffer, len(points)); err != nil {
		return err
	}
	for i := range points {
		if validatePoints && !cvValidG1(&points[i], true) {
			return fmt.Errorf("invalid CV-sAPVSS proof point %d", i)
		}
		cvWritePoint(buffer, &points[i])
	}
	return nil
}

func cvWriteScalarVector(buffer *bytes.Buffer, scalars []fr.Element) error {
	if err := cvWriteUint32(buffer, len(scalars)); err != nil {
		return err
	}
	for i := range scalars {
		cvWriteScalar(buffer, &scalars[i])
	}
	return nil
}

func cvWriteExactRangeProof(buffer *bytes.Buffer, proof *cvExactRangeProof) error {
	if proof == nil {
		return fmt.Errorf("nil CV-sAPVSS exact range proof")
	}
	if err := cvWritePointVector(buffer, proof.commitments); err != nil {
		return err
	}
	if err := cvWriteUint32(buffer, len(proof.bits)); err != nil {
		return err
	}
	for i := range proof.bits {
		bit := &proof.bits[i]
		for _, point := range []*bls12381.G1Affine{&bit.t0, &bit.t1} {
			if !cvValidG1(point, true) {
				return fmt.Errorf("invalid CV-sAPVSS exact range bit point %d", i)
			}
			cvWritePoint(buffer, point)
		}
		for _, scalar := range []*fr.Element{&bit.e0, &bit.z0, &bit.z1} {
			cvWriteScalar(buffer, scalar)
		}
	}
	if err := cvWriteUint32(buffer, len(proof.links)); err != nil {
		return err
	}
	for i := range proof.links {
		link := &proof.links[i]
		if !cvValidG1(&link.tCoin, true) {
			return fmt.Errorf("invalid CV-sAPVSS exact range coin point %d", i)
		}
		cvWritePoint(buffer, &link.tCoin)
		if err := cvWritePointVector(buffer, link.tCommitments); err != nil {
			return err
		}
		if err := cvWritePointVector(buffer, link.tCiphertexts); err != nil {
			return err
		}
		cvWriteScalar(buffer, &link.zCoin)
		if err := cvWriteScalarVector(buffer, link.zDigits); err != nil {
			return err
		}
		if err := cvWriteScalarVector(buffer, link.zRhos); err != nil {
			return err
		}
	}
	return nil
}

func cvLeafProofCanonicalBytes(proof *cvLeafProof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS Leaf proof")
	}
	var wire bytes.Buffer
	for _, point := range []*bls12381.G1Affine{
		&proof.sharing.fScalar,
		&proof.sharing.fBlinding,
		&proof.sharing.a,
		&proof.sharing.yScalar,
		&proof.sharing.yBlinding,
		&proof.chunking.y0,
	} {
		if !cvValidG1(point, point != &proof.chunking.y0) {
			return nil, fmt.Errorf("invalid CV-sAPVSS Leaf proof point")
		}
		cvWritePoint(&wire, point)
	}
	for _, scalar := range []*fr.Element{
		&proof.sharing.zScalar,
		&proof.sharing.zBlinding,
		&proof.sharing.zScalarCoin,
		&proof.sharing.zBlindingCoin,
	} {
		cvWriteScalar(&wire, scalar)
	}
	if err := cvWritePointVector(&wire, proof.chunking.b); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.chunking.c); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.chunking.d); err != nil {
		return nil, err
	}
	if !cvValidG1(&proof.chunking.y, true) {
		return nil, fmt.Errorf("invalid CV-sAPVSS chunk proof Y")
	}
	cvWritePoint(&wire, &proof.chunking.y)
	if err := cvWriteScalarVector(&wire, proof.chunking.zCoins); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.chunking.zDigits); err != nil {
		return nil, err
	}
	cvWriteScalar(&wire, &proof.chunking.zBeta)
	if err := cvWriteExactRangeProof(&wire, &proof.chunking.exactRange); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvTranscriptBytes(parts ...[]byte) []byte {
	var wire bytes.Buffer
	for _, part := range parts {
		_ = cvWriteBytes(&wire, part)
	}
	return wire.Bytes()
}

func cvHashToFr(domain string, parts ...[]byte) (fr.Element, error) {
	elements, err := fr.Hash(cvTranscriptBytes(parts...), []byte(domain), 1)
	if err != nil {
		return fr.Element{}, fmt.Errorf("hash CV-sAPVSS transcript to fr: %w", err)
	}
	return elements[0], nil
}

func cvLeafStatementDigest(leaf *cvLeaf) ([]byte, error) {
	wire, err := cvLeafStatementBytes(leaf)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvLeafStatementDigestDomain), wire), nil
}

func cvFrPowers(base fr.Element, count int) []fr.Element {
	powers := make([]fr.Element, count)
	if count == 0 {
		return powers
	}
	powers[0].SetOne()
	for i := 1; i < count; i++ {
		powers[i].Mul(&powers[i-1], &base)
	}
	return powers
}

func cvLinearScalars(values, weights []fr.Element) fr.Element {
	var result fr.Element
	for i := range values {
		var term fr.Element
		term.Mul(&values[i], &weights[i])
		result.Add(&result, &term)
	}
	return result
}

func cvLinearPoints(points []bls12381.G1Affine, weights []fr.Element) bls12381.G1Affine {
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range points {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&points[i], weights[i].BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result
}

func cvPointTimes(point *bls12381.G1Affine, scalar *fr.Element) bls12381.G1Affine {
	var result bls12381.G1Affine
	result.ScalarMultiplication(point, scalar.BigInt(new(big.Int)))
	return result
}

func cvPointJointTimes(
	first *bls12381.G1Affine, firstScalar *fr.Element,
	second *bls12381.G1Affine, secondScalar *fr.Element,
) bls12381.G1Affine {
	var jacobian bls12381.G1Jac
	jacobian.JointScalarMultiplication(
		first, second, firstScalar.BigInt(new(big.Int)), secondScalar.BigInt(new(big.Int)),
	)
	var result bls12381.G1Affine
	result.FromJacobian(&jacobian)
	return result
}

func cvPointBaseAndTimes(
	baseScalar *fr.Element, point *bls12381.G1Affine, pointScalar *fr.Element,
) bls12381.G1Affine {
	var jacobian bls12381.G1Jac
	jacobian.JointScalarMultiplicationBase(
		point, baseScalar.BigInt(new(big.Int)), pointScalar.BigInt(new(big.Int)),
	)
	var result bls12381.G1Affine
	result.FromJacobian(&jacobian)
	return result
}

func cvPointSum(points ...*bls12381.G1Affine) bls12381.G1Affine {
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for _, point := range points {
		result.Add(&result, point)
	}
	return result
}

func cvAffineOffsetEqualsTwoScalarSum(
	offset, first *bls12381.G1Affine,
	firstScalar *fr.Element,
	second *bls12381.G1Affine,
	secondScalar *fr.Element,
) bool {
	var negSecond bls12381.G1Affine
	negSecond.Neg(second)
	var result bls12381.G1Jac
	result.JointScalarMultiplication(
		first,
		&negSecond,
		firstScalar.BigInt(new(big.Int)),
		secondScalar.BigInt(new(big.Int)),
	)
	result.AddMixed(offset)
	return result.Z.IsZero()
}

func cvReconstructedCiphertexts(leaf *cvLeaf) (bls12381.G1Affine, []bls12381.G1Affine, error) {
	base, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return bls12381.G1Affine{}, nil, err
	}
	if len(leaf.receivers) == 0 {
		return bls12381.G1Affine{}, nil, fmt.Errorf("empty CV-sAPVSS receiver list")
	}
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	firstComponents := make([]bls12381.G1Affine, chunks)
	for chunk := 0; chunk < chunks; chunk++ {
		firstComponents[chunk] = leaf.receivers[0].encryptedShare.scalarChunks[chunk].r
		for receiver := 1; receiver < len(leaf.receivers); receiver++ {
			if !leaf.receivers[receiver].encryptedShare.scalarChunks[chunk].r.Equal(&firstComponents[chunk]) {
				return bls12381.G1Affine{}, nil, fmt.Errorf("CV-sAPVSS Groth chunk coin is not shared")
			}
		}
	}
	for receiver := 1; receiver < len(leaf.receivers); receiver++ {
		if !leaf.receivers[receiver].encryptedShare.blinding.r.Equal(
			&leaf.receivers[0].encryptedShare.blinding.r,
		) {
			return bls12381.G1Affine{}, nil, fmt.Errorf("CV-sAPVSS Groth blinding coin is not shared")
		}
	}

	first := cvLinearPoints(firstComponents, powers)
	seconds := make([]bls12381.G1Affine, len(leaf.receivers))
	for receiver := range leaf.receivers {
		components := make([]bls12381.G1Affine, chunks)
		for chunk := range components {
			components[chunk] = leaf.receivers[receiver].encryptedShare.scalarChunks[chunk].c
		}
		seconds[receiver] = cvLinearPoints(components, powers)
	}
	return first, seconds, nil
}

type cvSharingProofInstance struct {
	statementDigest    []byte
	scalarCoinBase     bls12381.G1Affine
	blindingCoinBase   bls12381.G1Affine
	commitment         bls12381.G1Affine
	publicKey          bls12381.G1Affine
	scalarCiphertext   bls12381.G1Affine
	blindingCiphertext bls12381.G1Affine
	weights            []fr.Element
}

func cvBuildSharingProofInstance(leaf *cvLeaf) (*cvSharingProofInstance, error) {
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		return nil, err
	}
	eta, err := cvHashToFr(cvSharingBatchDomain, statementDigest)
	if err != nil {
		return nil, err
	}
	weights := cvFrPowers(eta, len(leaf.receivers))
	chunkCoinBase, scalarCiphertexts, err := cvReconstructedCiphertexts(leaf)
	if err != nil {
		return nil, err
	}
	blindingCoinBase := leaf.receivers[0].encryptedShare.blinding.r

	commitments := make([]bls12381.G1Affine, len(leaf.receivers))
	keys := make([]bls12381.G1Affine, len(leaf.receivers))
	scalarCiphertextsWeighted := make([]bls12381.G1Affine, len(leaf.receivers))
	blindingCiphertexts := make([]bls12381.G1Affine, len(leaf.receivers))
	for i := range leaf.receivers {
		commitments[i] = leaf.receivers[i].encryptedShare.commitment
		keys[i] = leaf.receivers[i].receiverPublicKey
		scalarCiphertextsWeighted[i] = scalarCiphertexts[i]
		blindingCiphertexts[i] = leaf.receivers[i].encryptedShare.blinding.c
	}
	return &cvSharingProofInstance{
		statementDigest:    statementDigest,
		scalarCoinBase:     chunkCoinBase,
		blindingCoinBase:   blindingCoinBase,
		commitment:         cvLinearPoints(commitments, weights),
		publicKey:          cvLinearPoints(keys, weights),
		scalarCiphertext:   cvLinearPoints(scalarCiphertextsWeighted, weights),
		blindingCiphertext: cvLinearPoints(blindingCiphertexts, weights),
		weights:            weights,
	}, nil
}

func cvSharingChallenge(statementDigest []byte, proof *cvSharingProof) (fr.Element, error) {
	var points bytes.Buffer
	cvWritePoint(&points, &proof.fScalar)
	cvWritePoint(&points, &proof.fBlinding)
	cvWritePoint(&points, &proof.a)
	cvWritePoint(&points, &proof.yScalar)
	cvWritePoint(&points, &proof.yBlinding)
	return cvHashToFr(cvSharingChallengeDomain, statementDigest, points.Bytes())
}

func cvProveSharing(
	leaf *cvLeaf,
	scalars, blindings, scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (cvSharingProof, error) {
	instance, err := cvBuildSharingProofInstance(leaf)
	if err != nil {
		return cvSharingProof{}, err
	}
	base, _, chunks, _ := cvProfile(leaf.context.profile)
	if len(scalars) != len(instance.weights) || len(blindings) != len(instance.weights) ||
		len(scalarCoins) != chunks {
		return cvSharingProof{}, fmt.Errorf("invalid CV-sAPVSS sharing witness shape")
	}
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	chunkWeights := cvFrPowers(baseScalar, chunks)
	aggregateScalar := cvLinearScalars(scalars, instance.weights)
	aggregateBlinding := cvLinearScalars(blindings, instance.weights)

	var randomScalar, randomBlinding, randomScalarCoin, randomBlindingCoin fr.Element
	for _, value := range []*fr.Element{&randomScalar, &randomBlinding, &randomScalarCoin, &randomBlindingCoin} {
		if _, err := value.SetRandom(); err != nil {
			return cvSharingProof{}, fmt.Errorf("sample CV-sAPVSS sharing proof randomness: %w", err)
		}
	}
	h, err := cvPedersenBase()
	if err != nil {
		return cvSharingProof{}, err
	}
	proof := cvSharingProof{}
	proof.fScalar.ScalarMultiplication(&genG1, randomScalarCoin.BigInt(new(big.Int)))
	proof.fBlinding.ScalarMultiplication(&genG1, randomBlindingCoin.BigInt(new(big.Int)))
	proof.a = cvPointSum(
		pointPtr(cvPointTimes(&genG1, &randomScalar)),
		pointPtr(cvPointTimes(&h, &randomBlinding)),
	)
	proof.yScalar = cvPointSum(
		pointPtr(cvPointTimes(&instance.publicKey, &randomScalarCoin)),
		pointPtr(cvPointTimes(&genG1, &randomScalar)),
	)
	proof.yBlinding = cvPointSum(
		pointPtr(cvPointTimes(&instance.publicKey, &randomBlindingCoin)),
		pointPtr(cvPointTimes(&h, &randomBlinding)),
	)
	challenge, err := cvSharingChallenge(instance.statementDigest, &proof)
	if err != nil {
		return cvSharingProof{}, err
	}
	proof.zScalar.Mul(&challenge, &aggregateScalar).Add(&proof.zScalar, &randomScalar)
	proof.zBlinding.Mul(&challenge, &aggregateBlinding).Add(&proof.zBlinding, &randomBlinding)
	chunkCoin := cvLinearScalars(scalarCoins, chunkWeights)
	proof.zScalarCoin.Mul(&challenge, &chunkCoin).Add(&proof.zScalarCoin, &randomScalarCoin)
	proof.zBlindingCoin.Mul(&challenge, &blindingCoin).Add(&proof.zBlindingCoin, &randomBlindingCoin)
	return proof, nil
}

func pointPtr(point bls12381.G1Affine) *bls12381.G1Affine {
	return &point
}

func cvVerifySharing(leaf *cvLeaf, proof *cvSharingProof) error {
	return cvVerifySharingPoints(leaf, proof, true)
}

func cvVerifySharingValidatedPoints(leaf *cvLeaf, proof *cvSharingProof) error {
	return cvVerifySharingPoints(leaf, proof, false)
}

func cvVerifySharingPoints(leaf *cvLeaf, proof *cvSharingProof, validatePoints bool) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.sharingVerifyCalls.Add(1)
	}
	if validatePoints {
		for _, point := range []*bls12381.G1Affine{
			&proof.fScalar, &proof.fBlinding, &proof.a, &proof.yScalar, &proof.yBlinding,
		} {
			if !cvValidG1(point, true) {
				return fmt.Errorf("invalid CV-sAPVSS sharing proof point")
			}
		}
	}
	instance, err := cvBuildSharingProofInstance(leaf)
	if err != nil {
		return err
	}
	challenge, err := cvSharingChallenge(instance.statementDigest, proof)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}

	lhs1 := cvPointTimes(&genG1, &proof.zScalarCoin)
	rhs1 := cvPointSum(&proof.fScalar, pointPtr(cvPointTimes(&instance.scalarCoinBase, &challenge)))
	if !lhs1.Equal(&rhs1) {
		return fmt.Errorf("invalid CV-sAPVSS sharing coin equation")
	}
	lhsCoinBlind := cvPointTimes(&genG1, &proof.zBlindingCoin)
	rhsCoinBlind := cvPointSum(&proof.fBlinding, pointPtr(cvPointTimes(&instance.blindingCoinBase, &challenge)))
	if !lhsCoinBlind.Equal(&rhsCoinBlind) {
		return fmt.Errorf("invalid CV-sAPVSS sharing blinding coin equation")
	}
	lhs2 := cvPointSum(
		pointPtr(cvPointTimes(&genG1, &proof.zScalar)),
		pointPtr(cvPointTimes(&h, &proof.zBlinding)),
	)
	rhs2 := cvPointSum(&proof.a, pointPtr(cvPointTimes(&instance.commitment, &challenge)))
	if !lhs2.Equal(&rhs2) {
		return fmt.Errorf("invalid CV-sAPVSS sharing commitment equation")
	}
	lhs3 := cvPointSum(
		pointPtr(cvPointTimes(&instance.publicKey, &proof.zScalarCoin)),
		pointPtr(cvPointTimes(&genG1, &proof.zScalar)),
	)
	rhs3 := cvPointSum(&proof.yScalar, pointPtr(cvPointTimes(&instance.scalarCiphertext, &challenge)))
	if !lhs3.Equal(&rhs3) {
		return fmt.Errorf("invalid CV-sAPVSS sharing ciphertext equation")
	}
	lhs4 := cvPointSum(
		pointPtr(cvPointTimes(&instance.publicKey, &proof.zBlindingCoin)),
		pointPtr(cvPointTimes(&h, &proof.zBlinding)),
	)
	rhs4 := cvPointSum(&proof.yBlinding, pointPtr(cvPointTimes(&instance.blindingCiphertext, &challenge)))
	if !lhs4.Equal(&rhs4) {
		return fmt.Errorf("invalid CV-sAPVSS sharing blinding ciphertext equation")
	}
	return nil
}

func cvChunkProofBounds(profile cvChunkProfile, receivers int) (*big.Int, *big.Int, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, nil, err
	}
	if receivers <= 0 {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS chunk proof receiver count")
	}
	s := new(big.Int).SetInt64(int64(receivers))
	s.Mul(s, new(big.Int).SetInt64(int64(chunks)))
	s.Mul(s, new(big.Int).SetUint64(base-1))
	s.Mul(s, new(big.Int).SetUint64(cvChunkChallengeMask))
	z := new(big.Int).Mul(new(big.Int).Set(s), big.NewInt(2*cvChunkProofRepetitions))
	if s.Sign() <= 0 || z.Cmp(fr.Modulus()) >= 0 {
		return nil, nil, fmt.Errorf("CV-sAPVSS chunk proof response bound exceeds fr")
	}
	return s, z, nil
}

func cvRangeBitIndex(chunks, bits, receiver, chunk, bit int) int {
	return (receiver*chunks+chunk)*bits + bit
}

func cvRangeCommitmentPoint(proof *cvExactRangeProof, receiver, chunk, chunks, bits int) bls12381.G1Affine {
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for bit := 0; bit < bits; bit++ {
		weight := new(big.Int).Lsh(big.NewInt(1), uint(bit))
		var term bls12381.G1Affine
		term.ScalarMultiplication(&proof.commitments[cvRangeBitIndex(chunks, bits, receiver, chunk, bit)], weight)
		result.Add(&result, &term)
	}
	return result
}

func cvExactRangeFirstBytes(proof *cvExactRangeProof, validatePoints bool) ([]byte, error) {
	var wire bytes.Buffer
	if err := cvWritePointVectorMode(&wire, proof.commitments, validatePoints); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(proof.bits)); err != nil {
		return nil, err
	}
	for i := range proof.bits {
		if validatePoints && (!cvValidG1(&proof.bits[i].t0, true) || !cvValidG1(&proof.bits[i].t1, true)) {
			return nil, fmt.Errorf("invalid CV-sAPVSS exact range first move bit %d", i)
		}
		cvWritePoint(&wire, &proof.bits[i].t0)
		cvWritePoint(&wire, &proof.bits[i].t1)
	}
	if err := cvWriteUint32(&wire, len(proof.links)); err != nil {
		return nil, err
	}
	for i := range proof.links {
		if validatePoints && !cvValidG1(&proof.links[i].tCoin, true) {
			return nil, fmt.Errorf("invalid CV-sAPVSS exact range first move coin %d", i)
		}
		cvWritePoint(&wire, &proof.links[i].tCoin)
		if err := cvWritePointVectorMode(&wire, proof.links[i].tCommitments, validatePoints); err != nil {
			return nil, err
		}
		if err := cvWritePointVectorMode(&wire, proof.links[i].tCiphertexts, validatePoints); err != nil {
			return nil, err
		}
	}
	return wire.Bytes(), nil
}

func cvExactRangeChallenge(statementDigest []byte, proof *cvExactRangeProof) (fr.Element, error) {
	return cvExactRangeChallengeMode(statementDigest, proof, true)
}

func cvExactRangeChallengeMode(statementDigest []byte, proof *cvExactRangeProof, validatePoints bool) (fr.Element, error) {
	first, err := cvExactRangeFirstBytes(proof, validatePoints)
	if err != nil {
		return fr.Element{}, err
	}
	return cvHashToFr(cvExactRangeDomain, statementDigest, first)
}

type cvExactRangeBitWitness struct {
	rho        fr.Element
	bit        uint8
	actualT    fr.Element
	simulatedE fr.Element
	simulatedZ fr.Element
}

func cvProveExactRange(
	leaf *cvLeaf,
	digits [][]uint64,
	scalarCoins []fr.Element,
) (cvExactRangeProof, error) {
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		return cvExactRangeProof{}, err
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return cvExactRangeProof{}, err
	}
	receivers := len(leaf.receivers)
	bits := int(leaf.context.profile.chunkBits)
	if len(digits) != receivers || len(scalarCoins) != chunks {
		return cvExactRangeProof{}, fmt.Errorf("invalid CV-sAPVSS exact range witness shape")
	}
	for receiver := range digits {
		if len(digits[receiver]) != chunks {
			return cvExactRangeProof{}, fmt.Errorf("invalid CV-sAPVSS exact range digit count")
		}
	}
	h, err := cvPedersenBase()
	if err != nil {
		return cvExactRangeProof{}, err
	}
	proof := cvExactRangeProof{
		commitments: make([]bls12381.G1Affine, receivers*chunks*bits),
		bits:        make([]cvBitProof, receivers*chunks*bits),
		links:       make([]cvRangeLinkProof, chunks),
	}
	witnesses := make([]cvExactRangeBitWitness, len(proof.bits))
	for receiver := 0; receiver < receivers; receiver++ {
		for chunk := 0; chunk < chunks; chunk++ {
			for bit := 0; bit < bits; bit++ {
				index := cvRangeBitIndex(chunks, bits, receiver, chunk, bit)
				w := &witnesses[index]
				w.bit = uint8((digits[receiver][chunk] >> uint(bit)) & 1)
				if _, err := w.rho.SetRandom(); err != nil {
					return cvExactRangeProof{}, err
				}
				var bitPoint bls12381.G1Affine
				bitPoint.ScalarMultiplication(&genG1, big.NewInt(int64(w.bit)))
				proof.commitments[index] = cvPointSum(
					pointPtr(bitPoint),
					pointPtr(cvPointTimes(&h, &w.rho)),
				)
				if _, err := w.actualT.SetRandom(); err != nil {
					return cvExactRangeProof{}, err
				}
				if _, err := w.simulatedE.SetRandom(); err != nil {
					return cvExactRangeProof{}, err
				}
				if _, err := w.simulatedZ.SetRandom(); err != nil {
					return cvExactRangeProof{}, err
				}
				bitProof := &proof.bits[index]
				if w.bit == 0 {
					bitProof.t0 = cvPointTimes(&h, &w.actualT)
					var branch bls12381.G1Affine
					branch.Sub(&proof.commitments[index], &genG1)
					bitProof.t1.Sub(
						pointPtr(cvPointTimes(&h, &w.simulatedZ)),
						pointPtr(cvPointTimes(&branch, &w.simulatedE)),
					)
				} else {
					bitProof.t1 = cvPointTimes(&h, &w.actualT)
					bitProof.t0.Sub(
						pointPtr(cvPointTimes(&h, &w.simulatedZ)),
						pointPtr(cvPointTimes(&proof.commitments[index], &w.simulatedE)),
					)
				}
			}
		}
	}
	linkRandomCoin := make([]fr.Element, chunks)
	linkRandomDigit := make([][]fr.Element, chunks)
	linkRandomRho := make([][]fr.Element, chunks)
	for chunk := 0; chunk < chunks; chunk++ {
		link := &proof.links[chunk]
		if _, err := linkRandomCoin[chunk].SetRandom(); err != nil {
			return cvExactRangeProof{}, err
		}
		link.tCoin.ScalarMultiplication(&genG1, linkRandomCoin[chunk].BigInt(new(big.Int)))
		link.tCommitments = make([]bls12381.G1Affine, receivers)
		link.tCiphertexts = make([]bls12381.G1Affine, receivers)
		linkRandomDigit[chunk] = make([]fr.Element, receivers)
		linkRandomRho[chunk] = make([]fr.Element, receivers)
		for receiver := 0; receiver < receivers; receiver++ {
			if _, err := linkRandomDigit[chunk][receiver].SetRandom(); err != nil {
				return cvExactRangeProof{}, err
			}
			if _, err := linkRandomRho[chunk][receiver].SetRandom(); err != nil {
				return cvExactRangeProof{}, err
			}
			pk := &leaf.receivers[receiver].receiverPublicKey
			link.tCommitments[receiver] = cvPointSum(
				pointPtr(cvPointTimes(&genG1, &linkRandomDigit[chunk][receiver])),
				pointPtr(cvPointTimes(&h, &linkRandomRho[chunk][receiver])),
			)
			link.tCiphertexts[receiver] = cvPointSum(
				pointPtr(cvPointTimes(pk, &linkRandomCoin[chunk])),
				pointPtr(cvPointTimes(&genG1, &linkRandomDigit[chunk][receiver])),
			)
		}
	}
	challenge, err := cvExactRangeChallengeMode(statementDigest, &proof, false)
	if err != nil {
		return cvExactRangeProof{}, err
	}
	for index := range proof.bits {
		w := &witnesses[index]
		bitProof := &proof.bits[index]
		if w.bit == 0 {
			bitProof.e0.Sub(&challenge, &w.simulatedE)
			bitProof.z0.Mul(&bitProof.e0, &w.rho).Add(&bitProof.z0, &w.actualT)
			bitProof.e0.Set(&bitProof.e0)
			bitProof.z1.Set(&w.simulatedZ)
		} else {
			bitProof.e0.Set(&w.simulatedE)
			bitProof.z0.Set(&w.simulatedZ)
			var e1 fr.Element
			e1.Sub(&challenge, &bitProof.e0)
			bitProof.z1.Mul(&e1, &w.rho).Add(&bitProof.z1, &w.actualT)
		}
	}
	for chunk := 0; chunk < chunks; chunk++ {
		link := &proof.links[chunk]
		if _, err := link.zCoin.SetRandom(); err != nil {
			return cvExactRangeProof{}, err
		}
		link.zCoin.Mul(&challenge, &scalarCoins[chunk]).Add(&link.zCoin, &linkRandomCoin[chunk])
		link.zDigits = make([]fr.Element, receivers)
		link.zRhos = make([]fr.Element, receivers)
		for receiver := 0; receiver < receivers; receiver++ {
			index := cvRangeBitIndex(chunks, bits, receiver, chunk, 0)
			var digit fr.Element
			digit.SetUint64(digits[receiver][chunk])
			link.zDigits[receiver].Mul(&challenge, &digit).Add(
				&link.zDigits[receiver], &linkRandomDigit[chunk][receiver],
			)
			var rhoSum fr.Element
			for bit := 0; bit < bits; bit++ {
				var weightScalar fr.Element
				weightScalar.SetUint64(uint64(1) << uint(bit))
				bitIndex := index + bit
				var term fr.Element
				term.Mul(&weightScalar, &witnesses[bitIndex].rho)
				rhoSum.Add(&rhoSum, &term)
			}
			link.zRhos[receiver].Mul(&challenge, &rhoSum).Add(&link.zRhos[receiver], &linkRandomRho[chunk][receiver])
		}
	}
	return proof, nil
}

func cvVerifyExactRange(leaf *cvLeaf, proof *cvExactRangeProof) error {
	return cvVerifyExactRangePoints(leaf, proof, true)
}

func cvVerifyExactRangeValidatedPoints(leaf *cvLeaf, proof *cvExactRangeProof) error {
	return cvVerifyExactRangePoints(leaf, proof, false)
}

func cvVerifyExactRangePoints(leaf *cvLeaf, proof *cvExactRangeProof, validatePoints bool) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.exactRangeVerifyCalls.Add(1)
	}
	if proof == nil {
		return fmt.Errorf("missing CV-sAPVSS exact range proof")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return err
	}
	receivers := len(leaf.receivers)
	bits := int(leaf.context.profile.chunkBits)
	wantBits := receivers * chunks * bits
	if len(proof.commitments) != wantBits || len(proof.bits) != wantBits || len(proof.links) != chunks {
		return fmt.Errorf("invalid CV-sAPVSS exact range proof shape")
	}
	for chunk := range proof.links {
		if len(proof.links[chunk].tCommitments) != receivers ||
			len(proof.links[chunk].tCiphertexts) != receivers ||
			len(proof.links[chunk].zDigits) != receivers ||
			len(proof.links[chunk].zRhos) != receivers {
			return fmt.Errorf("invalid CV-sAPVSS exact range link shape %d", chunk)
		}
	}
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		return err
	}
	challenge, err := cvExactRangeChallengeMode(statementDigest, proof, validatePoints)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	for index := range proof.bits {
		bit := &proof.bits[index]
		var e1 fr.Element
		e1.Sub(&challenge, &bit.e0)
		branch1 := proof.commitments[index]
		branch1.Sub(&branch1, &genG1)
		if !cvAffineOffsetEqualsTwoScalarSum(&bit.t0, &proof.commitments[index], &bit.e0, &h, &bit.z0) {
			return fmt.Errorf("invalid CV-sAPVSS exact range zero branch %d", index)
		}
		if !cvAffineOffsetEqualsTwoScalarSum(&bit.t1, &branch1, &e1, &h, &bit.z1) {
			return fmt.Errorf("invalid CV-sAPVSS exact range one branch %d", index)
		}
	}
	for chunk := 0; chunk < chunks; chunk++ {
		link := &proof.links[chunk]
		for receiver := 0; receiver < receivers; receiver++ {
			r := &leaf.receivers[receiver].encryptedShare.scalarChunks[chunk].r
			var lhsCoin bls12381.G1Affine
			lhsCoin = cvPointSum(&link.tCoin, pointPtr(cvPointTimes(r, &challenge)))
			rhsCoin := cvPointTimes(&genG1, &link.zCoin)
			if !lhsCoin.Equal(&rhsCoin) {
				return fmt.Errorf("invalid CV-sAPVSS exact range coin link %d/%d", chunk, receiver)
			}
			var dPoint bls12381.G1Affine
			dPoint = cvRangeCommitmentPoint(proof, receiver, chunk, chunks, bits)
			lhsCommitment := cvPointSum(
				&link.tCommitments[receiver],
				pointPtr(cvPointTimes(&dPoint, &challenge)),
			)
			rhsCommitment := cvPointSum(
				pointPtr(cvPointTimes(&genG1, &link.zDigits[receiver])),
				pointPtr(cvPointTimes(&h, &link.zRhos[receiver])),
			)
			if !lhsCommitment.Equal(&rhsCommitment) {
				return fmt.Errorf("invalid CV-sAPVSS exact range commitment link %d/%d", chunk, receiver)
			}
			ciphertext := &leaf.receivers[receiver].encryptedShare.scalarChunks[chunk].c
			lhsCiphertext := cvPointSum(
				&link.tCiphertexts[receiver],
				pointPtr(cvPointTimes(ciphertext, &challenge)),
			)
			rhsCiphertext := cvPointSum(
				pointPtr(cvPointTimes(&leaf.receivers[receiver].receiverPublicKey, &link.zCoin)),
				pointPtr(cvPointTimes(&genG1, &link.zDigits[receiver])),
			)
			if !lhsCiphertext.Equal(&rhsCiphertext) {
				return fmt.Errorf("invalid CV-sAPVSS exact range ciphertext link %d/%d", chunk, receiver)
			}
		}
	}
	return nil
}

func cvChunkFirstChallenges(
	statementDigest []byte,
	y0 *bls12381.G1Affine,
	b, c []bls12381.G1Affine,
	receivers, chunks int,
) (cvChunkChallenges, []byte, error) {
	var firstMove bytes.Buffer
	cvWritePoint(&firstMove, y0)
	if err := cvWritePointVectorMode(&firstMove, b, false); err != nil {
		return nil, nil, err
	}
	if err := cvWritePointVectorMode(&firstMove, c, false); err != nil {
		return nil, nil, err
	}
	seed := hashBytes([]byte(cvChunkFirstDomain), statementDigest, firstMove.Bytes())
	challenges := make(cvChunkChallenges, receivers)
	var challengeWire bytes.Buffer
	for receiver := 0; receiver < receivers; receiver++ {
		challenges[receiver] = make([][]uint16, chunks)
		for chunk := 0; chunk < chunks; chunk++ {
			challenges[receiver][chunk] = make([]uint16, cvChunkProofRepetitions)
			for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
				var index [12]byte
				binary.BigEndian.PutUint32(index[0:4], uint32(receiver))
				binary.BigEndian.PutUint32(index[4:8], uint32(chunk))
				binary.BigEndian.PutUint32(index[8:12], uint32(repetition))
				digest := hashBytes(seed, index[:])
				value := uint16(digest[0]) & cvChunkChallengeMask
				challenges[receiver][chunk][repetition] = value
				_ = challengeWire.WriteByte(byte(value))
			}
		}
	}
	return challenges, hashBytes([]byte(cvChunkFirstDomain+"/digest"), challengeWire.Bytes()), nil
}

func cvChunkSecondChallenge(
	statementDigest, firstChallengeDigest []byte,
	zDigits []fr.Element,
	d []bls12381.G1Affine,
	y *bls12381.G1Affine,
) (fr.Element, error) {
	var secondMove bytes.Buffer
	if err := cvWriteScalarVector(&secondMove, zDigits); err != nil {
		return fr.Element{}, err
	}
	if err := cvWritePointVectorMode(&secondMove, d, false); err != nil {
		return fr.Element{}, err
	}
	cvWritePoint(&secondMove, y)
	return cvHashToFr(cvChunkSecondDomain, statementDigest, firstChallengeDigest, secondMove.Bytes())
}

func cvChallengeWeight(challenges cvChunkChallenges, powers []fr.Element, receiver, chunk int) fr.Element {
	var result fr.Element
	for repetition := range powers {
		var challenge fr.Element
		challenge.SetUint64(uint64(challenges[receiver][chunk][repetition]))
		challenge.Mul(&challenge, &powers[repetition])
		result.Add(&result, &challenge)
	}
	return result
}

func cvRandomSigned(s, z *big.Int) (*big.Int, error) {
	rangeSize := new(big.Int).Add(new(big.Int).Set(s), z)
	value, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return nil, err
	}
	return value.Sub(value, s), nil
}

func cvProveChunking(
	leaf *cvLeaf,
	digits [][]uint64,
	scalarCoins []fr.Element,
) (cvChunkingProof, error) {
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		return cvChunkingProof{}, err
	}
	_, _, chunks, _ := cvProfile(leaf.context.profile)
	receivers := len(leaf.receivers)
	if len(digits) != receivers || len(scalarCoins) != chunks {
		return cvChunkingProof{}, fmt.Errorf("invalid CV-sAPVSS chunk witness shape")
	}
	for i := range digits {
		if len(digits[i]) != chunks {
			return cvChunkingProof{}, fmt.Errorf("invalid CV-sAPVSS digit count")
		}
	}
	s, z, err := cvChunkProofBounds(leaf.context.profile, receivers)
	if err != nil {
		return cvChunkingProof{}, err
	}

	y0, err := bls12381.HashToG1(statementDigest, []byte(cvChunkY0Domain))
	if err != nil {
		return cvChunkingProof{}, err
	}
	if !cvValidG1(&y0, false) || y0.Equal(&genG1) {
		return cvChunkingProof{}, fmt.Errorf("invalid statement-derived CV-sAPVSS chunk base")
	}

	beta := make([]fr.Element, cvChunkProofRepetitions)
	b := make([]bls12381.G1Affine, cvChunkProofRepetitions)
	for i := range beta {
		if _, err := beta[i].SetRandom(); err != nil {
			return cvChunkingProof{}, err
		}
		b[i].ScalarMultiplication(&genG1, beta[i].BigInt(new(big.Int)))
	}

	var c []bls12381.G1Affine
	var challenges cvChunkChallenges
	var firstChallengeDigest []byte
	var zDigits []fr.Element
	accepted := false
	for attempt := 0; attempt < 256 && !accepted; attempt++ {
		sigma := make([]*big.Int, cvChunkProofRepetitions)
		c = make([]bls12381.G1Affine, cvChunkProofRepetitions)
		for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
			sigma[repetition], err = cvRandomSigned(s, z)
			if err != nil {
				return cvChunkingProof{}, err
			}
			var sigmaScalar fr.Element
			sigmaScalar.SetBigInt(sigma[repetition])
			c[repetition] = cvPointSum(
				pointPtr(cvPointTimes(&y0, &beta[repetition])),
				pointPtr(cvPointTimes(&genG1, &sigmaScalar)),
			)
		}
		challenges, firstChallengeDigest, err = cvChunkFirstChallenges(
			statementDigest,
			&y0,
			b,
			c,
			receivers,
			chunks,
		)
		if err != nil {
			return cvChunkingProof{}, err
		}
		zDigits = make([]fr.Element, cvChunkProofRepetitions)
		accepted = true
		for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
			response := new(big.Int).Set(sigma[repetition])
			for receiver := 0; receiver < receivers; receiver++ {
				for chunk := 0; chunk < chunks; chunk++ {
					term := new(big.Int).SetUint64(uint64(challenges[receiver][chunk][repetition]))
					term.Mul(term, new(big.Int).SetUint64(digits[receiver][chunk]))
					response.Add(response, term)
				}
			}
			if response.Sign() < 0 || response.Cmp(z) >= 0 {
				accepted = false
				break
			}
			zDigits[repetition].SetBigInt(response)
		}
	}
	if !accepted {
		return cvChunkingProof{}, fmt.Errorf("CV-sAPVSS chunk proof rejection sampling exhausted")
	}

	delta := make([]fr.Element, receivers+1)
	d := make([]bls12381.G1Affine, len(delta))
	for i := range delta {
		if _, err := delta[i].SetRandom(); err != nil {
			return cvChunkingProof{}, err
		}
		d[i].ScalarMultiplication(&genG1, delta[i].BigInt(new(big.Int)))
	}
	y := cvPointTimes(&y0, &delta[0])
	for receiver := 0; receiver < receivers; receiver++ {
		term := cvPointTimes(&leaf.receivers[receiver].receiverPublicKey, &delta[receiver+1])
		y.Add(&y, &term)
	}
	x, err := cvChunkSecondChallenge(statementDigest, firstChallengeDigest, zDigits, d, &y)
	if err != nil {
		return cvChunkingProof{}, err
	}
	xPowers := cvFrPowers(x, cvChunkProofRepetitions)
	zCoins := make([]fr.Element, receivers)
	for receiver := 0; receiver < receivers; receiver++ {
		zCoins[receiver] = delta[receiver+1]
		for chunk := 0; chunk < chunks; chunk++ {
			weight := cvChallengeWeight(challenges, xPowers, receiver, chunk)
			var term fr.Element
			term.Mul(&scalarCoins[chunk], &weight)
			zCoins[receiver].Add(&zCoins[receiver], &term)
		}
	}
	zBeta := delta[0]
	for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
		var term fr.Element
		term.Mul(&beta[repetition], &xPowers[repetition])
		zBeta.Add(&zBeta, &term)
	}
	return cvChunkingProof{
		y0:      y0,
		b:       b,
		c:       c,
		d:       d,
		y:       y,
		zCoins:  zCoins,
		zDigits: zDigits,
		zBeta:   zBeta,
	}, nil
}

func cvVerifyChunking(leaf *cvLeaf, proof *cvChunkingProof) error {
	return cvVerifyChunkingPoints(leaf, proof, true)
}

func cvVerifyChunkingValidatedPoints(leaf *cvLeaf, proof *cvChunkingProof) error {
	return cvVerifyChunkingPoints(leaf, proof, false)
}

func cvVerifyChunkingPoints(leaf *cvLeaf, proof *cvChunkingProof, validatePoints bool) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.chunkingVerifyCalls.Add(1)
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return err
	}
	receivers := len(leaf.receivers)
	if len(proof.b) != cvChunkProofRepetitions || len(proof.c) != cvChunkProofRepetitions ||
		len(proof.d) != receivers+1 || len(proof.zCoins) != receivers ||
		len(proof.zDigits) != cvChunkProofRepetitions {
		return fmt.Errorf("invalid CV-sAPVSS chunk proof shape")
	}
	if (validatePoints && (!cvValidG1(&proof.y0, false) || !cvValidG1(&proof.y, true))) || proof.y0.Equal(&genG1) {
		return fmt.Errorf("invalid CV-sAPVSS chunk proof base")
	}
	if validatePoints {
		for _, points := range [][]bls12381.G1Affine{proof.b, proof.c, proof.d} {
			for i := range points {
				if !cvValidG1(&points[i], true) {
					return fmt.Errorf("invalid CV-sAPVSS chunk proof point")
				}
			}
		}
	}
	_, z, err := cvChunkProofBounds(leaf.context.profile, receivers)
	if err != nil {
		return err
	}
	for i := range proof.zDigits {
		if proof.zDigits[i].BigInt(new(big.Int)).Cmp(z) >= 0 {
			return fmt.Errorf("CV-sAPVSS chunk response outside statistical range")
		}
	}
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		return err
	}
	expectedY0, err := bls12381.HashToG1(statementDigest, []byte(cvChunkY0Domain))
	if err != nil || !proof.y0.Equal(&expectedY0) {
		return fmt.Errorf("CV-sAPVSS chunk base is not statement-derived")
	}
	challenges, firstChallengeDigest, err := cvChunkFirstChallenges(
		statementDigest,
		&proof.y0,
		proof.b,
		proof.c,
		receivers,
		chunks,
	)
	if err != nil {
		return err
	}
	x, err := cvChunkSecondChallenge(statementDigest, firstChallengeDigest, proof.zDigits, proof.d, &proof.y)
	if err != nil {
		return err
	}
	xPowers := cvFrPowers(x, cvChunkProofRepetitions)

	for receiver := 0; receiver < receivers; receiver++ {
		lhs := proof.d[receiver+1]
		for chunk := 0; chunk < chunks; chunk++ {
			weight := cvChallengeWeight(challenges, xPowers, receiver, chunk)
			term := cvPointTimes(&leaf.receivers[0].encryptedShare.scalarChunks[chunk].r, &weight)
			lhs.Add(&lhs, &term)
		}
		rhs := cvPointTimes(&genG1, &proof.zCoins[receiver])
		if !lhs.Equal(&rhs) {
			return fmt.Errorf("invalid CV-sAPVSS chunk coin equation at receiver %d", receiver+1)
		}
	}
	lhsBeta := proof.d[0]
	for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
		term := cvPointTimes(&proof.b[repetition], &xPowers[repetition])
		lhsBeta.Add(&lhsBeta, &term)
	}
	rhsBeta := cvPointTimes(&genG1, &proof.zBeta)
	if !lhsBeta.Equal(&rhsBeta) {
		return fmt.Errorf("invalid CV-sAPVSS chunk beta equation")
	}

	lhs := proof.y
	for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
		inner := proof.c[repetition]
		for receiver := 0; receiver < receivers; receiver++ {
			for chunk := 0; chunk < chunks; chunk++ {
				var challenge fr.Element
				challenge.SetUint64(uint64(challenges[receiver][chunk][repetition]))
				term := cvPointTimes(
					&leaf.receivers[receiver].encryptedShare.scalarChunks[chunk].c,
					&challenge,
				)
				inner.Add(&inner, &term)
			}
		}
		term := cvPointTimes(&inner, &xPowers[repetition])
		lhs.Add(&lhs, &term)
	}
	var digitResponse fr.Element
	for repetition := 0; repetition < cvChunkProofRepetitions; repetition++ {
		var term fr.Element
		term.Mul(&proof.zDigits[repetition], &xPowers[repetition])
		digitResponse.Add(&digitResponse, &term)
	}
	rhs := cvPointTimes(&proof.y0, &proof.zBeta)
	for receiver := 0; receiver < receivers; receiver++ {
		term := cvPointTimes(&leaf.receivers[receiver].receiverPublicKey, &proof.zCoins[receiver])
		rhs.Add(&rhs, &term)
	}
	digitTerm := cvPointTimes(&genG1, &digitResponse)
	rhs.Add(&rhs, &digitTerm)
	if !lhs.Equal(&rhs) {
		return fmt.Errorf("invalid CV-sAPVSS chunk ciphertext equation")
	}
	return nil
}

func cvProveLeaf(
	leaf *cvLeaf,
	scalars, blindings, scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (*cvLeafProof, error) {
	if leaf == nil || leaf.context.proofProfile != cvLeafGrothProofProfile {
		return nil, fmt.Errorf("invalid CV-sAPVSS M1-B proof request")
	}
	digits := make([][]uint64, len(scalars))
	for i := range scalars {
		var err error
		digits[i], err = cvScalarDigits(scalars[i], leaf.context.profile)
		if err != nil {
			return nil, err
		}
	}
	sharing, err := cvProveSharing(leaf, scalars, blindings, scalarCoins, blindingCoin)
	if err != nil {
		return nil, err
	}
	chunking, err := cvProveChunking(leaf, digits, scalarCoins)
	if err != nil {
		return nil, err
	}
	chunking.exactRange, err = cvProveExactRange(leaf, digits, scalarCoins)
	if err != nil {
		return nil, err
	}
	return &cvLeafProof{sharing: sharing, chunking: chunking}, nil
}

func cvVerifyLeafProof(leaf *cvLeaf) error {
	if leaf == nil || leaf.proof == nil || leaf.context.proofProfile != cvLeafGrothProofProfile {
		return fmt.Errorf("missing CV-sAPVSS M1-B leaf proof")
	}
	if err := cvVerifySharingValidatedPoints(leaf, &leaf.proof.sharing); err != nil {
		return err
	}
	if err := cvVerifyChunkingValidatedPoints(leaf, &leaf.proof.chunking); err != nil {
		return err
	}
	return cvVerifyExactRangeValidatedPoints(leaf, &leaf.proof.chunking.exactRange)
}
