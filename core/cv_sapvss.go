package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type cvEvaluationPowerKey struct {
	degree, receivers int
}

var cvEvaluationPowerCache sync.Map

type cvDigitPointTableEntry struct {
	once   sync.Once
	points []bls12381.G1Affine
	err    error
}

var cvDigitPointTables sync.Map

var (
	cvPedersenBaseOnce  sync.Once
	cvPedersenBaseValue bls12381.G1Affine
	cvPedersenBaseErr   error
)

const (
	cvMaxChunkBits                = 20
	cvMaxDLogBound                = uint64(1) << 32
	cvLeafStructuralProofProfile  = "m1a-feldman-structural-v2"
	cvLeafGrothProofProfile       = "m1b-groth-32x8-exact-range"
	cvLeafFullCompactProofProfile = "m1c-pedersen-full-compact-batch-experimental-v1"
	cvLeafFullFieldProofProfile   = "m1d-pedersen-full-field-congruent-experimental-v1"
	cvLeafContextDigestDomain     = "ARL-CV-sAPVSS/context"
	cvLeafStatementDigestDomain   = "ARL-CV-sAPVSS/statement"
	cvLeafDigestDomain            = "ARL-CV-sAPVSS/leaf"
	cvLeafReceiverRegistryDomain  = "ARL-CV-sAPVSS/registry"
	cvLeafGroupID                 = "BLS12-381-G1/fr"
)

type cvChunkProfile struct {
	chunkBits     uint
	maxComponents int
}

type cvElGamalCiphertext struct {
	r bls12381.G1Affine
	c bls12381.G1Affine
}

type cvEncryptedShare struct {
	receiverPublicKey bls12381.G1Affine
	scalarChunks      []cvElGamalCiphertext
	blinding          cvElGamalCiphertext
	commitment        bls12381.G1Affine
}

type cvDecryptedShare struct {
	scalar          fr.Element
	publicScalar    bls12381.G1Affine
	blindingOpening bls12381.G1Affine
}

type cvLeafContext struct {
	sessionID                 []byte
	epoch                     uint64
	previousStateDigest       []byte
	sharingDegree             int
	profile                   cvChunkProfile
	receiverPublicKeys        []bls12381.G1Affine
	receiverSigningPublicKeys []bls12381.G1Affine
	dealerSetPolicy           []byte
	proofProfile              string
}

type cvLeafReceiver struct {
	receiverIndex     int
	receiverPublicKey bls12381.G1Affine
	encryptedShare    *cvEncryptedShare
}

type cvLeaf struct {
	context                cvLeafContext
	dealerID               uint64
	coefficientCommitments []bls12381.G1Affine
	receivers              []cvLeafReceiver
	hasLeafNIZK            bool
	proof                  *cvLeafProof
	compactProof           *apvssCompactFallbackProof
	digest                 []byte
}

func cvProfile(profile cvChunkProfile) (uint64, uint64, int, error) {
	if profile.chunkBits == 0 || profile.chunkBits > cvMaxChunkBits || profile.maxComponents <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid CV-sAPVSS chunk profile")
	}
	base := uint64(1) << profile.chunkBits
	maxDigit := base - 1
	if uint64(profile.maxComponents) > ^uint64(0)/maxDigit {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS digit bound overflows")
	}
	bound := uint64(profile.maxComponents) * maxDigit
	if new(big.Int).SetUint64(bound).Cmp(fr.Modulus()) >= 0 {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS digit bound wraps scalar field")
	}
	if bound > cvMaxDLogBound {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS bounded-DLog range is infeasible")
	}
	chunks := (fr.Modulus().BitLen() + int(profile.chunkBits) - 1) / int(profile.chunkBits)
	return base, bound, chunks, nil
}

func cvChunkCount(profile cvChunkProfile) (int, error) {
	_, _, chunks, err := cvProfile(profile)
	return chunks, err
}

func cvValidG1(point *bls12381.G1Affine, allowInfinity bool) bool {
	return point != nil && point.IsOnCurve() && point.IsInSubGroup() &&
		(allowInfinity || !point.IsInfinity())
}

func cvReceiverPublicKey(secret fr.Element) (bls12381.G1Affine, error) {
	if secret.IsZero() {
		return bls12381.G1Affine{}, fmt.Errorf("CV-sAPVSS receiver secret must be nonzero")
	}
	var publicKey bls12381.G1Affine
	publicKey.ScalarMultiplication(&genG1, secret.BigInt(new(big.Int)))
	return publicKey, nil
}

func cvPedersenBase() (bls12381.G1Affine, error) {
	cvPedersenBaseOnce.Do(func() {
		cvPedersenBaseValue, cvPedersenBaseErr = bls12381.HashToG1(
			[]byte("ARL-CV-sAPVSS-Pedersen-H"),
			[]byte("ARL-CV-sAPVSS-H2C"),
		)
		if cvPedersenBaseErr != nil {
			cvPedersenBaseErr = fmt.Errorf("derive CV-sAPVSS Pedersen base: %w", cvPedersenBaseErr)
			return
		}
		if !cvValidG1(&cvPedersenBaseValue, false) || cvPedersenBaseValue.Equal(&genG1) {
			cvPedersenBaseErr = fmt.Errorf("invalid CV-sAPVSS Pedersen base")
		}
	})
	return cvPedersenBaseValue, cvPedersenBaseErr
}

func cvEncryptPoint(receiverPK, message *bls12381.G1Affine, coin fr.Element) (cvElGamalCiphertext, error) {
	if !cvValidG1(receiverPK, false) || !cvValidG1(message, true) {
		return cvElGamalCiphertext{}, fmt.Errorf("invalid CV-sAPVSS ElGamal point")
	}
	var coinInt big.Int
	coin.BigInt(&coinInt)
	var r, shared, c bls12381.G1Affine
	r.ScalarMultiplication(&genG1, &coinInt)
	shared.ScalarMultiplication(receiverPK, &coinInt)
	c.Add(&shared, message)
	return cvElGamalCiphertext{r: r, c: c}, nil
}

func cvDigitPointTable(profile cvChunkProfile) ([]bls12381.G1Affine, error) {
	base, _, _, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if profile.chunkBits > 12 {
		return nil, nil
	}
	value, _ := cvDigitPointTables.LoadOrStore(profile.chunkBits, &cvDigitPointTableEntry{})
	entry := value.(*cvDigitPointTableEntry)
	entry.once.Do(func() {
		entry.points = make([]bls12381.G1Affine, int(base))
		if len(entry.points) > 1 {
			entry.points[1] = genG1
		}
		for i := 2; i < len(entry.points); i++ {
			entry.points[i].Add(&entry.points[i-1], &genG1)
		}
	})
	return entry.points, entry.err
}

func cvSharedEncryptionCoins(
	scalarCoins [][]fr.Element,
	blindingCoins []fr.Element,
	chunks int,
) ([]fr.Element, fr.Element, bool) {
	if len(scalarCoins) == 0 || len(blindingCoins) != len(scalarCoins) ||
		len(scalarCoins[0]) != chunks {
		return nil, fr.Element{}, false
	}
	for receiver := range scalarCoins {
		if len(scalarCoins[receiver]) != chunks ||
			!blindingCoins[receiver].Equal(&blindingCoins[0]) {
			return nil, fr.Element{}, false
		}
		for chunk := range scalarCoins[0] {
			if !scalarCoins[receiver][chunk].Equal(&scalarCoins[0][chunk]) {
				return nil, fr.Element{}, false
			}
		}
	}
	return scalarCoins[0], blindingCoins[0], true
}

func cvEncryptSharesSharedCoins(
	profile cvChunkProfile,
	receiverKeys []bls12381.G1Affine,
	scalars, blindings []fr.Element,
	commonCoins []fr.Element,
	commonBlindingCoin fr.Element,
) ([]*cvEncryptedShare, error) {
	_, _, chunks, err := cvProfile(profile)
	if err != nil || len(receiverKeys) != len(scalars) || len(scalars) != len(blindings) ||
		len(commonCoins) != chunks {
		return nil, fmt.Errorf("invalid shared-coin CV-sAPVSS encryption input")
	}
	digitTable, err := cvDigitPointTable(profile)
	if err != nil {
		return nil, err
	}
	coins := make([]fr.Element, chunks+1)
	copy(coins, commonCoins)
	coins[chunks] = commonBlindingCoin
	commonR := bls12381.BatchScalarMultiplicationG1(&genG1, coins)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	shares := make([]*cvEncryptedShare, len(receiverKeys))
	for receiver := range receiverKeys {
		if !cvValidG1(&receiverKeys[receiver], false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver public key")
		}
		digits, digitErr := cvScalarDigits(scalars[receiver], profile)
		if digitErr != nil {
			return nil, digitErr
		}
		shared := bls12381.BatchScalarMultiplicationG1(&receiverKeys[receiver], coins)
		ciphertexts := make([]cvElGamalCiphertext, chunks)
		var digitInt big.Int
		for chunk, digit := range digits {
			var digitPoint bls12381.G1Affine
			if digitTable != nil {
				digitPoint = digitTable[digit]
			} else {
				digitInt.SetUint64(digit)
				digitPoint.ScalarMultiplication(&genG1, &digitInt)
			}
			ciphertexts[chunk].r = commonR[chunk]
			ciphertexts[chunk].c.Add(&shared[chunk], &digitPoint)
		}
		var blindingPoint, scalarPoint, commitment bls12381.G1Affine
		var scalarInt, blindingInt big.Int
		blindings[receiver].BigInt(&blindingInt)
		blindingPoint.ScalarMultiplication(&h, &blindingInt)
		scalars[receiver].BigInt(&scalarInt)
		scalarPoint.ScalarMultiplication(&genG1, &scalarInt)
		commitment.Add(&scalarPoint, &blindingPoint)
		var blindingCiphertext cvElGamalCiphertext
		blindingCiphertext.r = commonR[chunks]
		blindingCiphertext.c.Add(&shared[chunks], &blindingPoint)
		shares[receiver] = &cvEncryptedShare{
			receiverPublicKey: receiverKeys[receiver],
			scalarChunks:      ciphertexts,
			blinding:          blindingCiphertext,
			commitment:        commitment,
		}
	}
	return shares, nil
}

func cvScalarDigits(scalar fr.Element, profile cvChunkProfile) ([]uint64, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	var remaining, mask, digit big.Int
	scalar.BigInt(&remaining)
	mask.SetUint64(base - 1)
	digits := make([]uint64, chunks)
	for i := range digits {
		digits[i] = digit.And(&remaining, &mask).Uint64()
		remaining.Rsh(&remaining, profile.chunkBits)
	}
	if remaining.Sign() != 0 {
		return nil, fmt.Errorf("CV-sAPVSS chunk count did not cover scalar")
	}
	return digits, nil
}

func cvReferenceEncryptShare(
	profile cvChunkProfile,
	receiverPK bls12381.G1Affine,
	scalar, blinding fr.Element,
	scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (*cvEncryptedShare, error) {
	if !cvValidG1(&receiverPK, false) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver public key")
	}
	digits, err := cvScalarDigits(scalar, profile)
	if err != nil {
		return nil, err
	}
	if len(scalarCoins) != len(digits) {
		return nil, fmt.Errorf("CV-sAPVSS scalar coin count mismatch")
	}

	chunks := make([]cvElGamalCiphertext, len(digits))
	var digitInt big.Int
	for i, digit := range digits {
		var digitPoint bls12381.G1Affine
		digitInt.SetUint64(digit)
		digitPoint.ScalarMultiplication(&genG1, &digitInt)
		chunks[i], err = cvEncryptPoint(&receiverPK, &digitPoint, scalarCoins[i])
		if err != nil {
			return nil, err
		}
	}

	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	var blindingPoint bls12381.G1Affine
	var blindingInt big.Int
	blinding.BigInt(&blindingInt)
	blindingPoint.ScalarMultiplication(&h, &blindingInt)
	blindingCiphertext, err := cvEncryptPoint(&receiverPK, &blindingPoint, blindingCoin)
	if err != nil {
		return nil, err
	}
	var scalarPoint, commitment bls12381.G1Affine
	var scalarInt big.Int
	scalar.BigInt(&scalarInt)
	scalarPoint.ScalarMultiplication(&genG1, &scalarInt)
	commitment.Add(&scalarPoint, &blindingPoint)

	return &cvEncryptedShare{
		receiverPublicKey: receiverPK,
		scalarChunks:      chunks,
		blinding:          blindingCiphertext,
		commitment:        commitment,
	}, nil
}

func cvValidCiphertext(ciphertext *cvElGamalCiphertext) bool {
	return ciphertext != nil && cvValidG1(&ciphertext.r, true) && cvValidG1(&ciphertext.c, true)
}

func cvIdentityCiphertext(ciphertext *cvElGamalCiphertext) bool {
	return cvValidCiphertext(ciphertext) && ciphertext.r.IsInfinity() && ciphertext.c.IsInfinity()
}

func cvValidateShare(share *cvEncryptedShare, chunks int) error {
	if share == nil || !cvValidG1(&share.receiverPublicKey, false) ||
		!cvValidG1(&share.commitment, true) || !cvValidCiphertext(&share.blinding) {
		return fmt.Errorf("invalid CV-sAPVSS encrypted share")
	}
	if len(share.scalarChunks) != chunks {
		return fmt.Errorf("CV-sAPVSS scalar chunk count mismatch")
	}
	for i := range share.scalarChunks {
		if !cvValidCiphertext(&share.scalarChunks[i]) {
			return fmt.Errorf("invalid CV-sAPVSS scalar chunk %d", i)
		}
	}
	return nil
}

func cvValidateShareForProfile(share *cvEncryptedShare, chunks int, proofProfile string) error {
	if err := cvValidateShare(share, chunks); err != nil {
		return err
	}
	if proofProfile == cvLeafStructuralProofProfile && !cvIdentityCiphertext(&share.blinding) {
		return fmt.Errorf("CV-sAPVSS structural share carries a non-identity blinding ciphertext")
	}
	return nil
}

func cvAggregate(profile cvChunkProfile, shares []*cvEncryptedShare) (*cvEncryptedShare, error) {
	_, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if len(shares) == 0 || len(shares) > profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate component count")
	}
	if err := cvValidateShare(shares[0], chunks); err != nil {
		return nil, err
	}
	result := &cvEncryptedShare{
		receiverPublicKey: shares[0].receiverPublicKey,
		scalarChunks:      append([]cvElGamalCiphertext(nil), shares[0].scalarChunks...),
		blinding:          shares[0].blinding,
		commitment:        shares[0].commitment,
	}
	for shareIndex := 1; shareIndex < len(shares); shareIndex++ {
		share := shares[shareIndex]
		if err := cvValidateShare(share, chunks); err != nil {
			return nil, err
		}
		if !share.receiverPublicKey.Equal(&result.receiverPublicKey) {
			return nil, fmt.Errorf("CV-sAPVSS aggregate mixes receiver keys")
		}
		for i := range result.scalarChunks {
			result.scalarChunks[i].r.Add(&result.scalarChunks[i].r, &share.scalarChunks[i].r)
			result.scalarChunks[i].c.Add(&result.scalarChunks[i].c, &share.scalarChunks[i].c)
		}
		result.blinding.r.Add(&result.blinding.r, &share.blinding.r)
		result.blinding.c.Add(&result.blinding.c, &share.blinding.c)
		result.commitment.Add(&result.commitment, &share.commitment)
	}
	return result, nil
}

func cvPointKey(point *bls12381.G1Affine) [bls12381.SizeOfG1AffineCompressed]byte {
	return point.Bytes()
}

type cvBoundedDLogSolver struct {
	bound         uint64
	width         uint64
	babies        map[[bls12381.SizeOfG1AffineCompressed]byte]uint64
	negativeGiant bls12381.G1Affine
}

func cvNewBoundedDLogSolver(bound uint64) *cvBoundedDLogSolver {
	rangeSize := bound + 1
	width := uint64(math.Ceil(math.Sqrt(float64(rangeSize))))
	for width*width < rangeSize {
		width++
	}

	solver := &cvBoundedDLogSolver{
		bound:  bound,
		width:  width,
		babies: make(map[[bls12381.SizeOfG1AffineCompressed]byte]uint64, width),
	}
	var current bls12381.G1Affine
	current.ScalarMultiplication(&genG1, big.NewInt(0))
	for j := uint64(0); j < width; j++ {
		solver.babies[cvPointKey(&current)] = j
		current.Add(&current, &genG1)
	}

	var giantStep bls12381.G1Affine
	giantStep.ScalarMultiplication(&genG1, new(big.Int).SetUint64(width))
	solver.negativeGiant.Neg(&giantStep)
	return solver
}

func (solver *cvBoundedDLogSolver) solve(target *bls12381.G1Affine) (uint64, bool) {
	if !cvValidG1(target, true) {
		return 0, false
	}
	var candidate bls12381.G1Affine
	candidate.Set(target)
	for i := uint64(0); i <= solver.width; i++ {
		if j, ok := solver.babies[cvPointKey(&candidate)]; ok {
			value := i*solver.width + j
			if value <= solver.bound {
				return value, true
			}
		}
		candidate.Add(&candidate, &solver.negativeGiant)
	}
	return 0, false
}

func cvBoundedDLog(target *bls12381.G1Affine, bound uint64) (uint64, bool) {
	return cvNewBoundedDLogSolver(bound).solve(target)
}

func cvDecryptShare(
	profile cvChunkProfile,
	receiverSecret fr.Element,
	aggregate *cvEncryptedShare,
	componentCount int,
) (*cvDecryptedShare, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if componentCount <= 0 || componentCount > profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS decrypt component count")
	}
	if err := cvValidateShare(aggregate, chunks); err != nil {
		return nil, err
	}
	receiverPK, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		return nil, err
	}
	if !receiverPK.Equal(&aggregate.receiverPublicKey) {
		return nil, fmt.Errorf("CV-sAPVSS receiver secret does not match key")
	}

	bound := uint64(componentCount) * (base - 1)
	solver := cvNewBoundedDLogSolver(bound)
	integerSum := new(big.Int)
	for i := range aggregate.scalarChunks {
		chunk := &aggregate.scalarChunks[i]
		var shared, message bls12381.G1Affine
		shared.ScalarMultiplication(&chunk.r, receiverSecret.BigInt(new(big.Int)))
		message.Sub(&chunk.c, &shared)
		digit, ok := solver.solve(&message)
		if !ok {
			return nil, fmt.Errorf("CV-sAPVSS bounded DLog failed for chunk %d", i)
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(i)*profile.chunkBits)
		integerSum.Add(integerSum, term)
	}
	integerSum.Mod(integerSum, fr.Modulus())
	var scalar fr.Element
	scalar.SetBigInt(integerSum)

	var blindingShared, blindingOpening, publicScalar bls12381.G1Affine
	blindingShared.ScalarMultiplication(&aggregate.blinding.r, receiverSecret.BigInt(new(big.Int)))
	blindingOpening.Sub(&aggregate.blinding.c, &blindingShared)
	publicScalar.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
	return &cvDecryptedShare{
		scalar:          scalar,
		publicScalar:    publicScalar,
		blindingOpening: blindingOpening,
	}, nil
}

func cvVerifyRelation(aggregate *cvEncryptedShare, decrypted *cvDecryptedShare) bool {
	if aggregate == nil || decrypted == nil || !cvValidG1(&aggregate.commitment, true) ||
		!cvValidG1(&decrypted.publicScalar, true) || !cvValidG1(&decrypted.blindingOpening, true) {
		return false
	}
	var expectedPublic, expectedCommitment bls12381.G1Affine
	expectedPublic.ScalarMultiplication(&genG1, decrypted.scalar.BigInt(new(big.Int)))
	expectedCommitment.Add(&decrypted.publicScalar, &decrypted.blindingOpening)
	return expectedPublic.Equal(&decrypted.publicScalar) && expectedCommitment.Equal(&aggregate.commitment)
}

func cvValidateLeafContext(context *cvLeafContext) error {
	if context == nil || len(context.sessionID) == 0 || len(context.dealerSetPolicy) == 0 ||
		(context.proofProfile != cvLeafStructuralProofProfile &&
			context.proofProfile != cvLeafGrothProofProfile &&
			context.proofProfile != cvLeafFullCompactProofProfile &&
			context.proofProfile != cvLeafFullFieldProofProfile) {
		return fmt.Errorf("invalid CV-sAPVSS Leaf context")
	}
	if _, _, _, err := cvProfile(context.profile); err != nil {
		return err
	}
	if len(context.previousStateDigest) != 0 && len(context.previousStateDigest) != 32 {
		return fmt.Errorf("invalid CV-sAPVSS previous-state digest")
	}
	if len(context.receiverPublicKeys) == 0 || len(context.receiverSigningPublicKeys) != len(context.receiverPublicKeys) || context.sharingDegree < 0 ||
		context.sharingDegree >= len(context.receiverPublicKeys) {
		return fmt.Errorf("invalid CV-sAPVSS Leaf sharing degree")
	}
	seen := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, len(context.receiverPublicKeys))
	for i := range context.receiverPublicKeys {
		key := &context.receiverPublicKeys[i]
		if !cvValidG1(key, false) {
			return fmt.Errorf("invalid CV-sAPVSS receiver key at index %d", i+1)
		}
		encoded := cvPointKey(key)
		if _, ok := seen[encoded]; ok {
			return fmt.Errorf("duplicate CV-sAPVSS receiver key at index %d", i+1)
		}
		seen[encoded] = struct{}{}
	}
	seenSigning := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, len(context.receiverPublicKeys))
	for i := range context.receiverSigningPublicKeys {
		signingKey := &context.receiverSigningPublicKeys[i]
		if !cvValidG1(signingKey, false) {
			return fmt.Errorf("invalid CV-sAPVSS receiver signing key at index %d", i+1)
		}
		encodedSigning := cvPointKey(signingKey)
		if _, ok := seenSigning[encodedSigning]; ok {
			return fmt.Errorf("duplicate CV-sAPVSS receiver signing key at index %d", i+1)
		}
		if _, ok := seen[encodedSigning]; ok {
			return fmt.Errorf("CV-sAPVSS receiver signing key reuses an encryption key at index %d", i+1)
		}
		seenSigning[encodedSigning] = struct{}{}
	}
	return nil
}

func cvWriteUint32(buffer *bytes.Buffer, value int) error {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return fmt.Errorf("CV-sAPVSS canonical length exceeds uint32")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(value))
	_, _ = buffer.Write(encoded[:])
	return nil
}

func cvWriteUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}

func cvWriteBytes(buffer *bytes.Buffer, value []byte) error {
	if err := cvWriteUint32(buffer, len(value)); err != nil {
		return err
	}
	_, _ = buffer.Write(value)
	return nil
}

func cvWritePoint(buffer *bytes.Buffer, point *bls12381.G1Affine) {
	encoded := point.Bytes()
	_, _ = buffer.Write(encoded[:])
}

func cvReceiverRegistryDigest(keys, signingKeys []bls12381.G1Affine) ([]byte, error) {
	if len(keys) == 0 || len(keys) != len(signingKeys) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver registry key count")
	}
	var wire bytes.Buffer
	if err := cvWriteUint32(&wire, len(keys)); err != nil {
		return nil, err
	}
	for i := range keys {
		if !cvValidG1(&keys[i], false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver key at index %d", i+1)
		}
		if err := cvWriteUint32(&wire, i+1); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &keys[i])
		if !cvValidG1(&signingKeys[i], false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver signing key at index %d", i+1)
		}
		cvWritePoint(&wire, &signingKeys[i])
	}
	return hashBytes([]byte(cvLeafReceiverRegistryDomain), wire.Bytes()), nil
}

func cvLeafContextCanonicalBytes(context *cvLeafContext) ([]byte, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	base, _, chunks, _ := cvProfile(context.profile)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	registryDigest, err := cvReceiverRegistryDigest(context.receiverPublicKeys, context.receiverSigningPublicKeys)
	if err != nil {
		return nil, err
	}

	var wire bytes.Buffer
	for _, value := range [][]byte{
		[]byte("ARL-CV-sAPVSS"),
		[]byte(cvLeafGroupID),
		fr.Modulus().Bytes(),
	} {
		if err := cvWriteBytes(&wire, value); err != nil {
			return nil, err
		}
	}
	cvWritePoint(&wire, &genG1)
	cvWritePoint(&wire, &h)
	if err := cvWriteBytes(&wire, context.sessionID); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, context.epoch)
	previousStateDigest := context.previousStateDigest
	if len(previousStateDigest) == 0 {
		previousStateDigest = make([]byte, 32)
	}
	if err := cvWriteBytes(&wire, previousStateDigest); err != nil {
		return nil, err
	}
	for _, value := range []int{
		len(context.receiverPublicKeys),
		context.sharingDegree,
		context.profile.maxComponents,
		int(context.profile.chunkBits),
		int(base),
		chunks,
	} {
		if err := cvWriteUint32(&wire, value); err != nil {
			return nil, err
		}
	}
	if err := cvWriteBytes(&wire, registryDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(context.receiverPublicKeys)); err != nil {
		return nil, err
	}
	for i := range context.receiverPublicKeys {
		if err := cvWriteUint32(&wire, i+1); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &context.receiverPublicKeys[i])
		cvWritePoint(&wire, &context.receiverSigningPublicKeys[i])
	}
	if err := cvWriteBytes(&wire, context.dealerSetPolicy); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, []byte(context.proofProfile)); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvLeafContextDigest(context *cvLeafContext) []byte {
	wire, err := cvLeafContextCanonicalBytes(context)
	if err != nil {
		return nil
	}
	return hashBytes([]byte(cvLeafContextDigestDomain), wire)
}

func cvCloneLeafContext(context cvLeafContext) cvLeafContext {
	context.sessionID = append([]byte(nil), context.sessionID...)
	context.previousStateDigest = append([]byte(nil), context.previousStateDigest...)
	context.receiverPublicKeys = append([]bls12381.G1Affine(nil), context.receiverPublicKeys...)
	context.receiverSigningPublicKeys = append([]bls12381.G1Affine(nil), context.receiverSigningPublicKeys...)
	context.dealerSetPolicy = append([]byte(nil), context.dealerSetPolicy...)
	return context
}

func cvReferenceDeal(
	context cvLeafContext,
	dealerID uint64,
	scalarCoefficients, blindingCoefficients []fr.Element,
	scalarCoins [][]fr.Element,
	blindingCoins []fr.Element,
) (*cvLeaf, error) {
	if err := cvValidateLeafContext(&context); err != nil {
		return nil, err
	}
	coefficientCount := context.sharingDegree + 1
	if len(scalarCoefficients) != coefficientCount || len(blindingCoefficients) != coefficientCount {
		return nil, fmt.Errorf("CV-sAPVSS polynomial coefficient count mismatch")
	}
	if len(scalarCoins) != len(context.receiverPublicKeys) ||
		len(blindingCoins) != len(context.receiverPublicKeys) {
		return nil, fmt.Errorf("CV-sAPVSS receiver coin count mismatch")
	}
	if context.proofProfile == cvLeafStructuralProofProfile {
		for i := range blindingCoefficients {
			if !blindingCoefficients[i].IsZero() {
				return nil, fmt.Errorf("CV-sAPVSS structural blinding coefficient %d is not zero", i)
			}
		}
		for i := range blindingCoins {
			if !blindingCoins[i].IsZero() {
				return nil, fmt.Errorf("CV-sAPVSS structural blinding coin %d is not zero", i+1)
			}
		}
	}
	if context.proofProfile == cvLeafGrothProofProfile {
		for receiver := 1; receiver < len(context.receiverPublicKeys); receiver++ {
			if len(scalarCoins[receiver]) != len(scalarCoins[0]) {
				return nil, fmt.Errorf("CV-sAPVSS Groth scalar coin count mismatch")
			}
			for chunk := range scalarCoins[0] {
				if !scalarCoins[receiver][chunk].Equal(&scalarCoins[0][chunk]) {
					return nil, fmt.Errorf("CV-sAPVSS Groth profile requires shared chunk coins")
				}
			}
			if !blindingCoins[receiver].Equal(&blindingCoins[0]) {
				return nil, fmt.Errorf("CV-sAPVSS Groth profile requires a shared blinding coin")
			}
		}
	}

	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	commitments := make([]bls12381.G1Affine, coefficientCount)
	for i := range commitments {
		var scalarTerm, blindingTerm bls12381.G1Affine
		var scalarInt, blindingInt big.Int
		scalarCoefficients[i].BigInt(&scalarInt)
		blindingCoefficients[i].BigInt(&blindingInt)
		scalarTerm.ScalarMultiplication(&genG1, &scalarInt)
		blindingTerm.ScalarMultiplication(&h, &blindingInt)
		commitments[i].Add(&scalarTerm, &blindingTerm)
	}

	receivers := make([]cvLeafReceiver, len(context.receiverPublicKeys))
	scalarEvaluations := make([]fr.Element, len(receivers))
	blindingEvaluations := make([]fr.Element, len(receivers))
	for i := range receivers {
		scalarEvaluations[i] = evalPolyInt(scalarCoefficients, int64(i+1))
		blindingEvaluations[i] = evalPolyInt(blindingCoefficients, int64(i+1))
	}
	encryptedShares := make([]*cvEncryptedShare, len(receivers))
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return nil, err
	}
	if commonCoins, commonBlindingCoin, shared := cvSharedEncryptionCoins(
		scalarCoins, blindingCoins, chunks,
	); shared {
		encryptedShares, err = cvEncryptSharesSharedCoins(
			context.profile,
			context.receiverPublicKeys,
			scalarEvaluations,
			blindingEvaluations,
			commonCoins,
			commonBlindingCoin,
		)
		if err != nil {
			return nil, err
		}
	} else {
		for i := range receivers {
			encryptedShares[i], err = cvReferenceEncryptShare(
				context.profile,
				context.receiverPublicKeys[i],
				scalarEvaluations[i],
				blindingEvaluations[i],
				scalarCoins[i],
				blindingCoins[i],
			)
			if err != nil {
				return nil, fmt.Errorf("encrypt CV-sAPVSS receiver %d: %w", i+1, err)
			}
		}
	}
	for i := range receivers {
		receivers[i] = cvLeafReceiver{
			receiverIndex:     i + 1,
			receiverPublicKey: context.receiverPublicKeys[i],
			encryptedShare:    encryptedShares[i],
		}
	}

	leaf := &cvLeaf{
		context:                cvCloneLeafContext(context),
		dealerID:               dealerID,
		coefficientCommitments: commitments,
		receivers:              receivers,
		hasLeafNIZK: context.proofProfile == cvLeafGrothProofProfile ||
			context.proofProfile == cvLeafFullCompactProofProfile ||
			context.proofProfile == cvLeafFullFieldProofProfile,
	}
	if context.proofProfile == cvLeafGrothProofProfile {
		leaf.proof, err = cvProveLeaf(
			leaf,
			scalarEvaluations,
			blindingEvaluations,
			scalarCoins[0],
			blindingCoins[0],
		)
		if err != nil {
			return nil, err
		}
	} else if context.proofProfile == cvLeafFullCompactProofProfile {
		indices := make([]int, len(receivers))
		for i := range indices {
			indices[i] = i + 1
		}
		leaf.compactProof, err = apvssProveCompactFallback(leaf, &apvssDealerWitness{
			scalars:       scalarEvaluations,
			blindings:     blindingEvaluations,
			scalarCoins:   scalarCoins,
			blindingCoins: blindingCoins,
		}, indices)
		if err != nil {
			return nil, err
		}
	} else if context.proofProfile == cvLeafFullFieldProofProfile {
		indices := make([]int, len(receivers))
		for i := range indices {
			indices[i] = i + 1
		}
		leaf.compactProof, err = apvssProveCompactFieldCongruent(leaf, &apvssDealerWitness{
			scalars: scalarEvaluations, blindings: blindingEvaluations,
			scalarCoins: scalarCoins, blindingCoins: blindingCoins,
		}, indices)
		if err != nil {
			return nil, err
		}
	}
	leaf.digest = cvLeafDigest(leaf)
	if leaf.digest == nil {
		return nil, fmt.Errorf("encode CV-sAPVSS Leaf")
	}
	return leaf, nil
}

func cvWriteCiphertext(buffer *bytes.Buffer, ciphertext *cvElGamalCiphertext) {
	cvWritePoint(buffer, &ciphertext.r)
	cvWritePoint(buffer, &ciphertext.c)
}

func cvLeafStatementBytes(leaf *cvLeaf) ([]byte, error) {
	if leaf == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS Leaf")
	}
	contextWire, err := cvLeafContextCanonicalBytes(&leaf.context)
	if err != nil {
		return nil, err
	}
	_, _, chunks, _ := cvProfile(leaf.context.profile)

	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, contextWire); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, leaf.dealerID)
	if err := cvWriteUint32(&wire, len(leaf.coefficientCommitments)); err != nil {
		return nil, err
	}
	for i := range leaf.coefficientCommitments {
		if !cvValidG1(&leaf.coefficientCommitments[i], true) {
			return nil, fmt.Errorf("invalid CV-sAPVSS coefficient commitment %d", i)
		}
		cvWritePoint(&wire, &leaf.coefficientCommitments[i])
	}
	if err := cvWriteUint32(&wire, len(leaf.receivers)); err != nil {
		return nil, err
	}
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		if receiver.receiverIndex <= 0 || !cvValidG1(&receiver.receiverPublicKey, false) ||
			receiver.encryptedShare == nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS Leaf receiver item %d", i)
		}
		if err := cvValidateShareForProfile(receiver.encryptedShare, chunks, leaf.context.proofProfile); err != nil {
			return nil, err
		}
		if err := cvWriteUint32(&wire, receiver.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &receiver.receiverPublicKey)
		cvWritePoint(&wire, &receiver.encryptedShare.receiverPublicKey)
		cvWritePoint(&wire, &receiver.encryptedShare.commitment)
		if err := cvWriteUint32(&wire, len(receiver.encryptedShare.scalarChunks)); err != nil {
			return nil, err
		}
		for chunkIndex := range receiver.encryptedShare.scalarChunks {
			cvWriteCiphertext(&wire, &receiver.encryptedShare.scalarChunks[chunkIndex])
		}
		if leaf.context.proofProfile != cvLeafStructuralProofProfile {
			cvWriteCiphertext(&wire, &receiver.encryptedShare.blinding)
		}
	}
	return wire.Bytes(), nil
}

func cvLeafCanonicalBytes(leaf *cvLeaf) ([]byte, error) {
	statement, err := cvLeafStatementBytes(leaf)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_, _ = wire.Write(statement)
	switch leaf.context.proofProfile {
	case cvLeafStructuralProofProfile:
		if leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS structural Leaf capability")
		}
		_ = wire.WriteByte(0)
	case cvLeafGrothProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof == nil || leaf.compactProof != nil {
			return nil, fmt.Errorf("missing CV-sAPVSS Leaf proof")
		}
		_ = wire.WriteByte(1)
		proofWire, err := cvLeafProofCanonicalBytes(leaf.proof)
		if err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	case cvLeafFullCompactProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof == nil {
			return nil, fmt.Errorf("missing CV-sAPVSS full compact proof")
		}
		_ = wire.WriteByte(2)
		proofWire, err := apvssCompactFallbackProofCanonicalBytes(leaf, leaf.compactProof)
		if err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	case cvLeafFullFieldProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof == nil {
			return nil, fmt.Errorf("missing CV-sAPVSS field-congruent proof")
		}
		_ = wire.WriteByte(3)
		proofWire, err := apvssCompactFieldProofCanonicalBytes(leaf, leaf.compactProof)
		if err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported CV-sAPVSS Leaf proof profile")
	}
	return wire.Bytes(), nil
}

func cvLeafDigest(leaf *cvLeaf) []byte {
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil
	}
	return hashBytes([]byte(cvLeafDigestDomain), wire)
}

func cvEvaluateCommitments(commitments []bls12381.G1Affine, receiverIndex int) bls12381.G1Affine {
	if len(commitments) == 0 || receiverIndex <= 0 {
		return bls12381.G1Affine{}
	}
	powers := cvEvaluationPowers(len(commitments), receiverIndex)
	return cvEvaluateCommitmentsWithPowers(commitments, powers[receiverIndex-1])
}

func cvEvaluationPowers(degree, receivers int) [][]fr.Element {
	if degree <= 0 || receivers <= 0 {
		return nil
	}
	key := cvEvaluationPowerKey{degree: degree, receivers: receivers}
	if cached, ok := cvEvaluationPowerCache.Load(key); ok {
		return cached.([][]fr.Element)
	}
	powers := make([][]fr.Element, receivers)
	for receiver := 1; receiver <= receivers; receiver++ {
		powers[receiver-1] = make([]fr.Element, degree)
		var x fr.Element
		x.SetInt64(int64(receiver))
		powers[receiver-1][0].SetOne()
		for index := 1; index < degree; index++ {
			powers[receiver-1][index].Mul(&powers[receiver-1][index-1], &x)
		}
	}
	actual, _ := cvEvaluationPowerCache.LoadOrStore(key, powers)
	return actual.([][]fr.Element)
}

func cvEvaluateCommitmentsWithPowers(commitments []bls12381.G1Affine, powers []fr.Element) bls12381.G1Affine {
	if len(commitments) != len(powers) || len(commitments) == 0 {
		return bls12381.G1Affine{}
	}
	if len(commitments) >= 32 {
		var result bls12381.G1Affine
		if _, err := result.MultiExp(commitments, powers, ecc.MultiExpConfig{
			NbTasks: cvNestedMSMWorkers(len(commitments)),
		}); err == nil {
			return result
		}
	}
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range commitments {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&commitments[i], powers[i].BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result
}

func cvVerifyLeaf(expectedContext *cvLeafContext, leaf *cvLeaf) error {
	expectedContextWire, err := cvLeafContextCanonicalBytes(expectedContext)
	if err != nil {
		return err
	}
	if leaf == nil {
		return fmt.Errorf("invalid CV-sAPVSS Leaf")
	}
	leafContextWire, err := cvLeafContextCanonicalBytes(&leaf.context)
	if err != nil {
		return err
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return err
	}
	return cvVerifyLeafCanonical(expectedContext, expectedContextWire, leafContextWire, leaf, wire)
}

func cvVerifyLeafCanonical(
	expectedContext *cvLeafContext,
	expectedContextWire, leafContextWire []byte,
	leaf *cvLeaf,
	canonicalWire []byte,
) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.leafVerifyCalls.Add(1)
	}
	if err := cvValidateLeafContext(expectedContext); err != nil {
		return err
	}
	if leaf == nil {
		return fmt.Errorf("invalid CV-sAPVSS Leaf")
	}
	switch expectedContext.proofProfile {
	case cvLeafStructuralProofProfile:
		if leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof != nil {
			return fmt.Errorf("invalid CV-sAPVSS structural Leaf capability")
		}
	case cvLeafGrothProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof == nil || leaf.compactProof != nil {
			return fmt.Errorf("missing CV-sAPVSS Leaf proof")
		}
	case cvLeafFullCompactProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof == nil {
			return fmt.Errorf("missing CV-sAPVSS full compact proof")
		}
	case cvLeafFullFieldProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof != nil || leaf.compactProof == nil || leaf.compactProof.comparator != nil {
			return fmt.Errorf("missing CV-sAPVSS field-congruent proof")
		}
	default:
		return fmt.Errorf("unsupported CV-sAPVSS Leaf proof profile")
	}
	if !bytes.Equal(expectedContextWire, leafContextWire) {
		return fmt.Errorf("CV-sAPVSS Leaf context mismatch")
	}
	if len(leaf.coefficientCommitments) != expectedContext.sharingDegree+1 ||
		len(leaf.receivers) != len(expectedContext.receiverPublicKeys) {
		return fmt.Errorf("CV-sAPVSS Leaf statement size mismatch")
	}
	_, _, chunks, _ := cvProfile(expectedContext.profile)
	for i := range leaf.coefficientCommitments {
		if !cvValidG1(&leaf.coefficientCommitments[i], true) {
			return fmt.Errorf("invalid CV-sAPVSS coefficient commitment %d", i)
		}
	}
	evaluationPowers := cvEvaluationPowers(len(leaf.coefficientCommitments), len(leaf.receivers))
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		expectedKey := &expectedContext.receiverPublicKeys[i]
		if receiver.receiverIndex != i+1 || !receiver.receiverPublicKey.Equal(expectedKey) ||
			receiver.encryptedShare == nil || !receiver.encryptedShare.receiverPublicKey.Equal(expectedKey) {
			return fmt.Errorf("CV-sAPVSS Leaf receiver binding mismatch at index %d", i+1)
		}
		if err := cvValidateShareForProfile(receiver.encryptedShare, chunks, expectedContext.proofProfile); err != nil {
			return err
		}
		expectedCommitment := cvEvaluateCommitmentsWithPowers(leaf.coefficientCommitments, evaluationPowers[i])
		if !receiver.encryptedShare.commitment.Equal(&expectedCommitment) {
			return fmt.Errorf("CV-sAPVSS Leaf evaluation commitment mismatch at index %d", i+1)
		}
	}
	expectedDigest := hashBytes([]byte(cvLeafDigestDomain), canonicalWire)
	if len(leaf.digest) != sha256.Size || !bytes.Equal(leaf.digest, expectedDigest) {
		return fmt.Errorf("CV-sAPVSS Leaf digest mismatch")
	}
	if expectedContext.proofProfile == cvLeafGrothProofProfile {
		if err := cvVerifyLeafProof(leaf); err != nil {
			return err
		}
	} else if expectedContext.proofProfile == cvLeafFullCompactProofProfile {
		if err := apvssVerifyCompactFallback(leaf, leaf.compactProof); err != nil {
			return fmt.Errorf("invalid CV-sAPVSS full compact proof: %w", err)
		}
	} else if expectedContext.proofProfile == cvLeafFullFieldProofProfile {
		if err := apvssVerifyCompactFieldCongruent(leaf, leaf.compactProof); err != nil {
			return fmt.Errorf("invalid CV-sAPVSS field-congruent proof: %w", err)
		}
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.leafVerifySuccesses.Add(1)
	}
	return nil
}
