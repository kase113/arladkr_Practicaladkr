package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssCompactRangeDomain       = "ARL-APVSS/compact-range"
	apvssCompactRangeGeneratorDST = "ARL-APVSS/compact-range/H2C"
)

type apvssCompactInnerProductProof struct {
	left  []bls12381.G1Affine
	right []bls12381.G1Affine
	a     fr.Element
	b     fr.Element
}

// apvssCompactRangeProof is an aggregated Bulletproof range proof. It may
// prove any positive number of same-width values; the implementation pads the
// value count to a power of two with public zero commitments.
type apvssCompactRangeProof struct {
	valueCount int
	bits       int
	a          bls12381.G1Affine
	s          bls12381.G1Affine
	t1         bls12381.G1Affine
	t2         bls12381.G1Affine
	tauX       fr.Element
	mu         fr.Element
	tHat       fr.Element
	inner      apvssCompactInnerProductProof
}

type apvssCompactRangeGenerators struct {
	g []bls12381.G1Affine
	h []bls12381.G1Affine
	u bls12381.G1Affine
}

var apvssCompactRangeGeneratorCache sync.Map

func apvssNextPowerOfTwo(value int) (int, error) {
	if value <= 0 || value > 1<<20 {
		return 0, fmt.Errorf("invalid APVSS compact vector size")
	}
	out := 1
	for out < value {
		out <<= 1
	}
	return out, nil
}

func apvssCompactRangeDimensions(valueCount, bits int) (int, int, error) {
	if valueCount <= 0 || bits <= 0 || bits > 63 {
		return 0, 0, fmt.Errorf("invalid APVSS compact range dimensions")
	}
	paddedValues, err := apvssNextPowerOfTwo(valueCount)
	if err != nil {
		return 0, 0, err
	}
	vectorSize, err := apvssNextPowerOfTwo(paddedValues * bits)
	if err != nil || vectorSize != paddedValues*bits {
		return 0, 0, fmt.Errorf("APVSS compact range width must be a power of two")
	}
	return paddedValues, vectorSize, nil
}

func apvssCompactRangeGenerator(kind byte, index int) (bls12381.G1Affine, error) {
	message := make([]byte, 9)
	message[0] = kind
	binary.BigEndian.PutUint64(message[1:], uint64(index))
	point, err := bls12381.HashToG1(message, []byte(apvssCompactRangeGeneratorDST))
	if err != nil || !cvValidG1(&point, false) || point.Equal(&genG1) {
		return bls12381.G1Affine{}, fmt.Errorf("derive APVSS compact range generator %d/%d", kind, index)
	}
	return point, nil
}

func apvssCompactRangeGeneratorsFor(size int) (*apvssCompactRangeGenerators, error) {
	if cached, ok := apvssCompactRangeGeneratorCache.Load(size); ok {
		return cached.(*apvssCompactRangeGenerators), nil
	}
	generators := &apvssCompactRangeGenerators{
		g: make([]bls12381.G1Affine, size),
		h: make([]bls12381.G1Affine, size),
	}
	var err error
	for i := 0; i < size; i++ {
		generators.g[i], err = apvssCompactRangeGenerator('G', i)
		if err != nil {
			return nil, err
		}
		generators.h[i], err = apvssCompactRangeGenerator('H', i)
		if err != nil {
			return nil, err
		}
	}
	generators.u, err = apvssCompactRangeGenerator('U', 0)
	if err != nil {
		return nil, err
	}
	actual, _ := apvssCompactRangeGeneratorCache.LoadOrStore(size, generators)
	return actual.(*apvssCompactRangeGenerators), nil
}

func apvssCompactIdentity() bls12381.G1Affine {
	var identity bls12381.G1Affine
	identity.ScalarMultiplication(&genG1, big.NewInt(0))
	return identity
}

func apvssCompactPointSum(points []bls12381.G1Affine, scalars []fr.Element) bls12381.G1Affine {
	if len(points) == len(scalars) && len(points) >= 32 {
		var out bls12381.G1Affine
		// Serial inner MSM: compact-range verification runs per lane inside
		// the leaf-verify worker pool; gnark task fan-out here oversubscribes
		// the outer workers without shortening the critical path.
		if _, err := out.MultiExp(points, scalars, ecc.MultiExpConfig{
			NbTasks: cvNestedMSMWorkers(len(points)),
		}); err == nil {
			return out
		}
	}
	out := apvssCompactIdentity()
	for i := range points {
		term := cvPointTimes(&points[i], &scalars[i])
		out.Add(&out, &term)
	}
	return out
}

func apvssCompactInnerProduct(left, right []fr.Element) fr.Element {
	var out fr.Element
	for i := range left {
		var term fr.Element
		term.Mul(&left[i], &right[i])
		out.Add(&out, &term)
	}
	return out
}

func apvssCompactScalarPowers(base fr.Element, count int) []fr.Element {
	out := make([]fr.Element, count)
	if count == 0 {
		return out
	}
	out[0].SetOne()
	for i := 1; i < count; i++ {
		out[i].Mul(&out[i-1], &base)
	}
	return out
}

func apvssCompactRangeBaseTranscript(
	statement []byte,
	commitments []bls12381.G1Affine,
	valueCount, bits int,
) ([]byte, error) {
	if len(statement) != 32 || len(commitments) != valueCount {
		return nil, fmt.Errorf("invalid APVSS compact range statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssCompactRangeDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, statement); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, valueCount); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, bits); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, commitments); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func apvssCompactChallenge(domain string, parts ...[]byte) (fr.Element, error) {
	challenge, err := cvHashToFr(domain, parts...)
	if err != nil {
		return fr.Element{}, err
	}
	if challenge.IsZero() {
		return fr.Element{}, fmt.Errorf("zero APVSS compact proof challenge")
	}
	return challenge, nil
}

func apvssCompactPointBytes(points ...*bls12381.G1Affine) []byte {
	var wire bytes.Buffer
	for _, point := range points {
		cvWritePoint(&wire, point)
	}
	return wire.Bytes()
}

func apvssCompactScalarBytes(scalars ...*fr.Element) []byte {
	var wire bytes.Buffer
	for _, scalar := range scalars {
		cvWriteScalar(&wire, scalar)
	}
	return wire.Bytes()
}

func apvssCompactRangeCommitment(value uint64, blinding fr.Element) (bls12381.G1Affine, error) {
	h, err := cvPedersenBase()
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	var scalar fr.Element
	scalar.SetUint64(value)
	return cvPointSum(
		pointPtr(cvPointTimes(&genG1, &scalar)),
		pointPtr(cvPointTimes(&h, &blinding)),
	), nil
}

func apvssProveCompactRange(
	statement []byte,
	commitments []bls12381.G1Affine,
	values []uint64,
	blindings []fr.Element,
	bits int,
) (*apvssCompactRangeProof, error) {
	if len(commitments) == 0 || len(commitments) != len(values) || len(values) != len(blindings) {
		return nil, fmt.Errorf("invalid APVSS compact range witness")
	}
	paddedValues, vectorSize, err := apvssCompactRangeDimensions(len(values), bits)
	if err != nil {
		return nil, err
	}
	if bits < 64 {
		limit := uint64(1) << uint(bits)
		for i, value := range values {
			if value >= limit {
				return nil, fmt.Errorf("APVSS compact range value %d is outside [0,2^%d)", i, bits)
			}
		}
	}
	for i := range values {
		expected, err := apvssCompactRangeCommitment(values[i], blindings[i])
		if err != nil || !expected.Equal(&commitments[i]) {
			return nil, fmt.Errorf("APVSS compact range opening mismatch %d", i)
		}
	}
	baseTranscript, err := apvssCompactRangeBaseTranscript(statement, commitments, len(values), bits)
	if err != nil {
		return nil, err
	}
	generators, err := apvssCompactRangeGeneratorsFor(vectorSize)
	if err != nil {
		return nil, err
	}
	hBlind, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	aL := make([]fr.Element, vectorSize)
	aR := make([]fr.Element, vectorSize)
	sL := make([]fr.Element, vectorSize)
	sR := make([]fr.Element, vectorSize)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var value uint64
		if valueIndex < len(values) {
			value = values[valueIndex]
		}
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			aL[index].SetUint64((value >> uint(bit)) & 1)
			one := fr.One()
			aR[index].Sub(&aL[index], &one)
		}
	}
	for i := range sL {
		sL[i], err = apvssRandomFr()
		if err != nil {
			return nil, err
		}
		sR[i], err = apvssRandomFr()
		if err != nil {
			return nil, err
		}
	}
	alpha, err := apvssRandomFr()
	if err != nil {
		return nil, err
	}
	rho, err := apvssRandomFr()
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactRangeProof{valueCount: len(values), bits: bits}
	proof.a = apvssCompactPointSum(generators.g, aL)
	proof.a.Add(&proof.a, pointPtr(apvssCompactPointSum(generators.h, aR)))
	proof.a.Add(&proof.a, pointPtr(cvPointTimes(&hBlind, &alpha)))
	proof.s = apvssCompactPointSum(generators.g, sL)
	proof.s.Add(&proof.s, pointPtr(apvssCompactPointSum(generators.h, sR)))
	proof.s.Add(&proof.s, pointPtr(cvPointTimes(&hBlind, &rho)))

	firstMove := apvssCompactPointBytes(&proof.a, &proof.s)
	y, err := apvssCompactChallenge(apvssCompactRangeDomain+"/y", baseTranscript, firstMove)
	if err != nil {
		return nil, err
	}
	yBytes := apvssCompactScalarBytes(&y)
	z, err := apvssCompactChallenge(apvssCompactRangeDomain+"/z", baseTranscript, firstMove, yBytes)
	if err != nil {
		return nil, err
	}
	yPowers := apvssCompactScalarPowers(y, vectorSize)
	zTwo := make([]fr.Element, vectorSize)
	var zPower fr.Element
	zPower.Mul(&z, &z)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var two fr.Element
		two.SetOne()
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			zTwo[index].Mul(&zPower, &two)
			two.Double(&two)
		}
		zPower.Mul(&zPower, &z)
	}
	l0 := make([]fr.Element, vectorSize)
	l1 := make([]fr.Element, vectorSize)
	r0 := make([]fr.Element, vectorSize)
	r1 := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		l0[i].Sub(&aL[i], &z)
		l1[i].Set(&sL[i])
		var shifted fr.Element
		shifted.Add(&aR[i], &z)
		r0[i].Mul(&yPowers[i], &shifted).Add(&r0[i], &zTwo[i])
		r1[i].Mul(&yPowers[i], &sR[i])
	}
	t1Left := apvssCompactInnerProduct(l1, r0)
	t1Right := apvssCompactInnerProduct(l0, r1)
	var t1, t2 fr.Element
	t1.Add(&t1Left, &t1Right)
	t2 = apvssCompactInnerProduct(l1, r1)
	tau1, err := apvssRandomFr()
	if err != nil {
		return nil, err
	}
	tau2, err := apvssRandomFr()
	if err != nil {
		return nil, err
	}
	proof.t1 = cvPointSum(pointPtr(cvPointTimes(&genG1, &t1)), pointPtr(cvPointTimes(&hBlind, &tau1)))
	proof.t2 = cvPointSum(pointPtr(cvPointTimes(&genG1, &t2)), pointPtr(cvPointTimes(&hBlind, &tau2)))
	secondMove := apvssCompactPointBytes(&proof.t1, &proof.t2)
	x, err := apvssCompactChallenge(
		apvssCompactRangeDomain+"/x", baseTranscript, firstMove, yBytes,
		apvssCompactScalarBytes(&z), secondMove,
	)
	if err != nil {
		return nil, err
	}
	var xSquared fr.Element
	xSquared.Mul(&x, &x)
	l := make([]fr.Element, vectorSize)
	r := make([]fr.Element, vectorSize)
	for i := range l {
		var term fr.Element
		term.Mul(&l1[i], &x)
		l[i].Add(&l0[i], &term)
		term.Mul(&r1[i], &x)
		r[i].Add(&r0[i], &term)
	}
	proof.tHat = apvssCompactInnerProduct(l, r)
	proof.tauX.Mul(&tau2, &xSquared)
	var tauTerm fr.Element
	tauTerm.Mul(&tau1, &x)
	proof.tauX.Add(&proof.tauX, &tauTerm)
	zPower.Mul(&z, &z)
	for i := 0; i < paddedValues; i++ {
		if i < len(blindings) {
			tauTerm.Mul(&zPower, &blindings[i])
			proof.tauX.Add(&proof.tauX, &tauTerm)
		}
		zPower.Mul(&zPower, &z)
	}
	proof.mu.Mul(&rho, &x).Add(&proof.mu, &alpha)
	w, err := apvssCompactChallenge(
		apvssCompactRangeDomain+"/w",
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytes(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
	)
	if err != nil {
		return nil, err
	}
	uPrime := cvPointTimes(&generators.u, &w)

	hPrime := make([]bls12381.G1Affine, vectorSize)
	var yInverse fr.Element
	yInverse.Inverse(&y)
	yInversePowers := apvssCompactScalarPowers(yInverse, vectorSize)
	for i := range hPrime {
		hPrime[i] = cvPointTimes(&generators.h[i], &yInversePowers[i])
	}
	p := proof.a
	p.Add(&p, pointPtr(cvPointTimes(&proof.s, &x)))
	var minusZ fr.Element
	minusZ.Neg(&z)
	gCoefficients := make([]fr.Element, vectorSize)
	hCoefficients := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		gCoefficients[i].Set(&minusZ)
		hCoefficients[i].Mul(&z, &yPowers[i]).Add(&hCoefficients[i], &zTwo[i])
	}
	p.Add(&p, pointPtr(apvssCompactPointSum(generators.g, gCoefficients)))
	p.Add(&p, pointPtr(apvssCompactPointSum(hPrime, hCoefficients)))
	var minusMu fr.Element
	minusMu.Neg(&proof.mu)
	p.Add(&p, pointPtr(cvPointTimes(&hBlind, &minusMu)))
	p.Add(&p, pointPtr(cvPointTimes(&uPrime, &proof.tHat)))
	innerPrefix := cvTranscriptBytes(
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytes(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
		apvssCompactPointBytes(&p),
	)
	proof.inner, err = apvssProveCompactInnerProduct(innerPrefix, generators.g, hPrime, uPrime, l, r)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func apvssCompactRangeDelta(y, z fr.Element, paddedValues, bits, vectorSize int) fr.Element {
	yPowers := apvssCompactScalarPowers(y, vectorSize)
	var sumY fr.Element
	for i := range yPowers {
		sumY.Add(&sumY, &yPowers[i])
	}
	var zSquared, first fr.Element
	zSquared.Mul(&z, &z)
	first.Sub(&z, &zSquared).Mul(&first, &sumY)
	var twoSum fr.Element
	twoSum.SetUint64((uint64(1) << uint(bits)) - 1)
	var subtract, zPower fr.Element
	zPower.Mul(&zSquared, &z)
	for i := 0; i < paddedValues; i++ {
		var term fr.Element
		term.Mul(&zPower, &twoSum)
		subtract.Add(&subtract, &term)
		zPower.Mul(&zPower, &z)
	}
	first.Sub(&first, &subtract)
	return first
}

func apvssVerifyCompactRange(
	statement []byte,
	commitments []bls12381.G1Affine,
	proof *apvssCompactRangeProof,
	bits int,
) error {
	if proof == nil || proof.valueCount != len(commitments) || proof.bits != bits {
		return fmt.Errorf("invalid APVSS compact range proof shape")
	}
	paddedValues, vectorSize, err := apvssCompactRangeDimensions(len(commitments), bits)
	if err != nil {
		return err
	}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		if !cvValidG1(point, true) {
			return fmt.Errorf("invalid APVSS compact range proof point")
		}
	}
	baseTranscript, err := apvssCompactRangeBaseTranscript(statement, commitments, len(commitments), bits)
	if err != nil {
		return err
	}
	firstMove := apvssCompactPointBytes(&proof.a, &proof.s)
	y, err := apvssCompactChallenge(apvssCompactRangeDomain+"/y", baseTranscript, firstMove)
	if err != nil {
		return err
	}
	yBytes := apvssCompactScalarBytes(&y)
	z, err := apvssCompactChallenge(apvssCompactRangeDomain+"/z", baseTranscript, firstMove, yBytes)
	if err != nil {
		return err
	}
	secondMove := apvssCompactPointBytes(&proof.t1, &proof.t2)
	x, err := apvssCompactChallenge(
		apvssCompactRangeDomain+"/x", baseTranscript, firstMove, yBytes,
		apvssCompactScalarBytes(&z), secondMove,
	)
	if err != nil {
		return err
	}
	hBlind, err := cvPedersenBase()
	if err != nil {
		return err
	}
	left := cvPointSum(
		pointPtr(cvPointTimes(&genG1, &proof.tHat)),
		pointPtr(cvPointTimes(&hBlind, &proof.tauX)),
	)
	delta := apvssCompactRangeDelta(y, z, paddedValues, bits, vectorSize)
	right := cvPointTimes(&genG1, &delta)
	var zPower fr.Element
	zPower.Mul(&z, &z)
	for i := 0; i < paddedValues; i++ {
		if i < len(commitments) {
			right.Add(&right, pointPtr(cvPointTimes(&commitments[i], &zPower)))
		}
		zPower.Mul(&zPower, &z)
	}
	right.Add(&right, pointPtr(cvPointTimes(&proof.t1, &x)))
	var xSquared fr.Element
	xSquared.Mul(&x, &x)
	right.Add(&right, pointPtr(cvPointTimes(&proof.t2, &xSquared)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid APVSS compact range polynomial commitment")
	}
	generators, err := apvssCompactRangeGeneratorsFor(vectorSize)
	if err != nil {
		return err
	}
	w, err := apvssCompactChallenge(
		apvssCompactRangeDomain+"/w",
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytes(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
	)
	if err != nil {
		return err
	}
	uPrime := cvPointTimes(&generators.u, &w)
	yPowers := apvssCompactScalarPowers(y, vectorSize)
	var yInverse fr.Element
	yInverse.Inverse(&y)
	yInversePowers := apvssCompactScalarPowers(yInverse, vectorSize)
	hPrime := make([]bls12381.G1Affine, vectorSize)
	for i := range hPrime {
		hPrime[i] = cvPointTimes(&generators.h[i], &yInversePowers[i])
	}
	zTwo := make([]fr.Element, vectorSize)
	zPower.Mul(&z, &z)
	for valueIndex := 0; valueIndex < paddedValues; valueIndex++ {
		var two fr.Element
		two.SetOne()
		for bit := 0; bit < bits; bit++ {
			index := valueIndex*bits + bit
			zTwo[index].Mul(&zPower, &two)
			two.Double(&two)
		}
		zPower.Mul(&zPower, &z)
	}
	p := proof.a
	p.Add(&p, pointPtr(cvPointTimes(&proof.s, &x)))
	var minusZ fr.Element
	minusZ.Neg(&z)
	gCoefficients := make([]fr.Element, vectorSize)
	hCoefficients := make([]fr.Element, vectorSize)
	for i := 0; i < vectorSize; i++ {
		gCoefficients[i].Set(&minusZ)
		hCoefficients[i].Mul(&z, &yPowers[i]).Add(&hCoefficients[i], &zTwo[i])
	}
	p.Add(&p, pointPtr(apvssCompactPointSum(generators.g, gCoefficients)))
	p.Add(&p, pointPtr(apvssCompactPointSum(hPrime, hCoefficients)))
	var minusMu fr.Element
	minusMu.Neg(&proof.mu)
	p.Add(&p, pointPtr(cvPointTimes(&hBlind, &minusMu)))
	p.Add(&p, pointPtr(cvPointTimes(&uPrime, &proof.tHat)))
	innerPrefix := cvTranscriptBytes(
		baseTranscript,
		firstMove,
		yBytes,
		apvssCompactScalarBytes(&z, &x, &proof.tauX, &proof.mu, &proof.tHat),
		secondMove,
		apvssCompactPointBytes(&p),
	)
	if err := apvssVerifyCompactInnerProduct(innerPrefix, generators.g, hPrime, uPrime, p, &proof.inner); err != nil {
		return fmt.Errorf("invalid APVSS compact range inner product: %w", err)
	}
	return nil
}

func apvssCompactInnerChallenge(prefix []byte, round int, left, right *bls12381.G1Affine) (fr.Element, error) {
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(round))
	return apvssCompactChallenge(
		apvssCompactRangeDomain+"/inner",
		prefix,
		index[:],
		apvssCompactPointBytes(left, right),
	)
}

func apvssProveCompactInnerProduct(
	prefix []byte,
	g, h []bls12381.G1Affine,
	u bls12381.G1Affine,
	a, b []fr.Element,
) (apvssCompactInnerProductProof, error) {
	if len(g) == 0 || len(g) != len(h) || len(g) != len(a) || len(a) != len(b) || len(g)&(len(g)-1) != 0 {
		return apvssCompactInnerProductProof{}, fmt.Errorf("invalid APVSS inner-product witness")
	}
	gWork := append([]bls12381.G1Affine(nil), g...)
	hWork := append([]bls12381.G1Affine(nil), h...)
	aWork := append([]fr.Element(nil), a...)
	bWork := append([]fr.Element(nil), b...)
	proof := apvssCompactInnerProductProof{}
	transcript := append([]byte(nil), prefix...)
	for round := 0; len(aWork) > 1; round++ {
		half := len(aWork) / 2
		aLeft, aRight := aWork[:half], aWork[half:]
		bLeft, bRight := bWork[:half], bWork[half:]
		left := apvssCompactPointSum(gWork[half:], aLeft)
		left.Add(&left, pointPtr(apvssCompactPointSum(hWork[:half], bRight)))
		leftInner := apvssCompactInnerProduct(aLeft, bRight)
		left.Add(&left, pointPtr(cvPointTimes(&u, &leftInner)))
		right := apvssCompactPointSum(gWork[:half], aRight)
		right.Add(&right, pointPtr(apvssCompactPointSum(hWork[half:], bLeft)))
		rightInner := apvssCompactInnerProduct(aRight, bLeft)
		right.Add(&right, pointPtr(cvPointTimes(&u, &rightInner)))
		proof.left = append(proof.left, left)
		proof.right = append(proof.right, right)
		roundPoints := apvssCompactPointBytes(&left, &right)
		x, err := apvssCompactInnerChallenge(transcript, round, &left, &right)
		if err != nil {
			return apvssCompactInnerProductProof{}, err
		}
		transcript = cvTranscriptBytes(transcript, roundPoints)
		var xInverse fr.Element
		xInverse.Inverse(&x)
		gNextJacobian := make([]bls12381.G1Jac, half)
		hNextJacobian := make([]bls12381.G1Jac, half)
		aNext := make([]fr.Element, half)
		bNext := make([]fr.Element, half)
		xBig := x.BigInt(new(big.Int))
		xInverseBig := xInverse.BigInt(new(big.Int))
		if err := cvRunParallelChecks(half, func(i int) error {
			gNextJacobian[i].JointScalarMultiplication(
				&gWork[i], &gWork[half+i], xInverseBig, xBig,
			)
			hNextJacobian[i].JointScalarMultiplication(
				&hWork[i], &hWork[half+i], xBig, xInverseBig,
			)
			return nil
		}); err != nil {
			return apvssCompactInnerProductProof{}, err
		}
		for i := 0; i < half; i++ {
			var term fr.Element
			aNext[i].Mul(&x, &aLeft[i])
			term.Mul(&xInverse, &aRight[i])
			aNext[i].Add(&aNext[i], &term)
			bNext[i].Mul(&xInverse, &bLeft[i])
			term.Mul(&x, &bRight[i])
			bNext[i].Add(&bNext[i], &term)
		}
		gNext := bls12381.BatchJacobianToAffineG1(gNextJacobian)
		hNext := bls12381.BatchJacobianToAffineG1(hNextJacobian)
		gWork, hWork, aWork, bWork = gNext, hNext, aNext, bNext
	}
	proof.a.Set(&aWork[0])
	proof.b.Set(&bWork[0])
	return proof, nil
}

func apvssVerifyCompactInnerProduct(
	prefix []byte,
	g, h []bls12381.G1Affine,
	u bls12381.G1Affine,
	p bls12381.G1Affine,
	proof *apvssCompactInnerProductProof,
) error {
	if proof == nil || len(g) == 0 || len(g) != len(h) || len(g)&(len(g)-1) != 0 ||
		len(proof.left) != len(proof.right) || 1<<uint(len(proof.left)) != len(g) {
		return fmt.Errorf("invalid APVSS inner-product proof shape")
	}
	transcript := append([]byte(nil), prefix...)
	challenges := make([]fr.Element, len(proof.left))
	inverseChallenges := make([]fr.Element, len(proof.left))
	leftCoefficients := make([]fr.Element, len(proof.left))
	rightCoefficients := make([]fr.Element, len(proof.left))
	for round := range proof.left {
		left, right := &proof.left[round], &proof.right[round]
		if !cvValidG1(left, true) || !cvValidG1(right, true) {
			return fmt.Errorf("invalid APVSS inner-product point %d", round)
		}
		roundPoints := apvssCompactPointBytes(left, right)
		x, err := apvssCompactInnerChallenge(transcript, round, left, right)
		if err != nil {
			return err
		}
		transcript = cvTranscriptBytes(transcript, roundPoints)
		challenges[round] = x
		inverseChallenges[round].Inverse(&x)
		leftCoefficients[round].Mul(&x, &x)
		rightCoefficients[round].Mul(
			&inverseChallenges[round], &inverseChallenges[round],
		)
	}

	// Expanding the recursive generator folds gives one coefficient per
	// original generator. Verify the same final equation with one MSM instead
	// of O(N log N) curve scalar multiplications.
	gWeights := make([]fr.Element, len(g))
	hWeights := make([]fr.Element, len(h))
	for generator := range g {
		gWeights[generator].SetOne()
		hWeights[generator].SetOne()
		half := len(g) / 2
		for round := range challenges {
			if generator&half == 0 {
				gWeights[generator].Mul(&gWeights[generator], &inverseChallenges[round])
				hWeights[generator].Mul(&hWeights[generator], &challenges[round])
			} else {
				gWeights[generator].Mul(&gWeights[generator], &challenges[round])
				hWeights[generator].Mul(&hWeights[generator], &inverseChallenges[round])
			}
			half >>= 1
		}
		gWeights[generator].Mul(&gWeights[generator], &proof.a).Neg(&gWeights[generator])
		hWeights[generator].Mul(&hWeights[generator], &proof.b).Neg(&hWeights[generator])
	}
	points := make([]bls12381.G1Affine, 0, 1+2*len(proof.left)+2*len(g)+1)
	coefficients := make([]fr.Element, 0, cap(points))
	points = append(points, p)
	coefficients = append(coefficients, fr.One())
	points = append(points, proof.left...)
	coefficients = append(coefficients, leftCoefficients...)
	points = append(points, proof.right...)
	coefficients = append(coefficients, rightCoefficients...)
	points = append(points, g...)
	coefficients = append(coefficients, gWeights...)
	points = append(points, h...)
	coefficients = append(coefficients, hWeights...)
	var product fr.Element
	product.Mul(&proof.a, &proof.b)
	product.Neg(&product)
	points = append(points, u)
	coefficients = append(coefficients, product)
	result := apvssCompactPointSum(points, coefficients)
	if !result.IsInfinity() {
		return fmt.Errorf("APVSS inner-product equation mismatch")
	}
	return nil
}

func apvssCompactRangeProofCanonicalBytes(proof *apvssCompactRangeProof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil APVSS compact range proof")
	}
	var wire bytes.Buffer
	if err := cvWriteUint32(&wire, proof.valueCount); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, proof.bits); err != nil {
		return nil, err
	}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		if !cvValidG1(point, true) {
			return nil, fmt.Errorf("invalid APVSS compact range point")
		}
		cvWritePoint(&wire, point)
	}
	for _, scalar := range []*fr.Element{&proof.tauX, &proof.mu, &proof.tHat} {
		cvWriteScalar(&wire, scalar)
	}
	if err := cvWriteUint32(&wire, len(proof.inner.left)); err != nil {
		return nil, err
	}
	for i := range proof.inner.left {
		cvWritePoint(&wire, &proof.inner.left[i])
		cvWritePoint(&wire, &proof.inner.right[i])
	}
	cvWriteScalar(&wire, &proof.inner.a)
	cvWriteScalar(&wire, &proof.inner.b)
	return wire.Bytes(), nil
}

func apvssDecodeCompactRangeProof(
	wire []byte,
	expectedValues, expectedBits int,
) (*apvssCompactRangeProof, error) {
	if len(wire) == 0 || len(wire) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid APVSS compact range wire")
	}
	r := newCVWireReader(wire)
	valueCount, err := r.uint32()
	if err != nil || valueCount != expectedValues {
		return nil, fmt.Errorf("invalid APVSS compact range value count")
	}
	bits, err := r.uint32()
	if err != nil || bits != expectedBits {
		return nil, fmt.Errorf("invalid APVSS compact range width")
	}
	_, vectorSize, err := apvssCompactRangeDimensions(valueCount, bits)
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactRangeProof{valueCount: valueCount, bits: bits}
	for _, point := range []*bls12381.G1Affine{&proof.a, &proof.s, &proof.t1, &proof.t2} {
		*point, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range point: %w", err)
		}
	}
	for _, scalar := range []*fr.Element{&proof.tauX, &proof.mu, &proof.tHat} {
		*scalar, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range scalar: %w", err)
		}
	}
	rounds, err := r.uint32()
	wantRounds := 0
	for size := vectorSize; size > 1; size >>= 1 {
		wantRounds++
	}
	if err != nil || rounds != wantRounds {
		return nil, fmt.Errorf("invalid APVSS compact range inner-product rounds")
	}
	proof.inner.left = make([]bls12381.G1Affine, rounds)
	proof.inner.right = make([]bls12381.G1Affine, rounds)
	for i := 0; i < rounds; i++ {
		proof.inner.left[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range inner left %d: %w", i, err)
		}
		proof.inner.right[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact range inner right %d: %w", i, err)
		}
	}
	proof.inner.a, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS compact range inner a: %w", err)
	}
	proof.inner.b, err = r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS compact range inner b or suffix")
	}
	canonical, err := apvssCompactRangeProofCanonicalBytes(proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS compact range proof")
	}
	return proof, nil
}
