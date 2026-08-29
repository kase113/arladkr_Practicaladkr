package core

import (
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// Point decoding defers subgroup checks and validates each decode unit with a
// Fiat-Shamir linear combination. Canonical gnark mask semantics are preserved.
const (
	cvG1Mask                 byte = 0b111 << 5
	cvG1Uncompressed         byte = 0b000 << 5
	cvG1UncompressedInfinity byte = 0b010 << 5
	cvG1CompressedSmallest   byte = 0b100 << 5
	cvG1CompressedLargest    byte = 0b101 << 5
	cvG1CompressedInfinity   byte = 0b110 << 5
)

func cvG1MaskInvalid(msb byte) bool {
	masked := msb & cvG1Mask
	return masked == (0b111<<5) || masked == (0b011<<5) || masked == (0b001<<5)
}

func cvG1BufferZeroed(firstByte byte, buf []byte) bool {
	if firstByte != 0 {
		return false
	}
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

// cvDecodeG1WireUnchecked decodes canonical G1 bytes without a subgroup check.
// Callers must subsequently call cvAssertG1SubgroupBatch.
func cvDecodeG1WireUnchecked(encoded []byte) (bls12381.G1Affine, error) {
	if len(encoded) < bls12381.SizeOfG1AffineCompressed {
		return bls12381.G1Affine{}, io.ErrShortBuffer
	}
	masked := encoded[0] & cvG1Mask
	if cvG1MaskInvalid(encoded[0]) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV point encoding mask")
	}
	if masked == cvG1CompressedInfinity {
		if !cvG1BufferZeroed(encoded[0] & ^cvG1Mask, encoded[1:bls12381.SizeOfG1AffineCompressed]) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV point infinity encoding")
		}
		return bls12381.G1Affine{}, nil
	}
	if masked == cvG1UncompressedInfinity {
		if len(encoded) < bls12381.SizeOfG1AffineUncompressed ||
			!cvG1BufferZeroed(encoded[0] & ^cvG1Mask, encoded[1:bls12381.SizeOfG1AffineUncompressed]) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV point infinity encoding")
		}
		return bls12381.G1Affine{}, nil
	}
	if masked == cvG1Uncompressed {
		if len(encoded) < bls12381.SizeOfG1AffineUncompressed {
			return bls12381.G1Affine{}, io.ErrShortBuffer
		}
		var point bls12381.G1Affine
		if err := point.X.SetBytesCanonical(encoded[:fp.Bytes]); err != nil {
			return bls12381.G1Affine{}, err
		}
		if err := point.Y.SetBytesCanonical(encoded[fp.Bytes : fp.Bytes*2]); err != nil {
			return bls12381.G1Affine{}, err
		}
		// Uncompressed input skips the square root, so curve membership is
		// not implied the way it is on the compressed path; check it here
		// before the point reaches the batch subgroup combination.
		var lhs, rhs fp.Element
		lhs.Square(&point.Y)
		rhs.Square(&point.X).Mul(&rhs, &point.X)
		// BLS12-381 G1 curve coefficient b is 4.
		rhs.Add(&rhs, new(fp.Element).SetUint64(4))
		if !lhs.Equal(&rhs) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV point not on curve")
		}
		return point, nil
	}
	var point bls12381.G1Affine
	var bufX [fp.Bytes]byte
	copy(bufX[:fp.Bytes], encoded[:fp.Bytes])
	bufX[0] &= ^cvG1Mask
	if err := point.X.SetBytesCanonical(bufX[:fp.Bytes]); err != nil {
		return bls12381.G1Affine{}, err
	}
	var ySquared, y fp.Element
	ySquared.Square(&point.X).Mul(&ySquared, &point.X)
	// BLS12-381 G1 curve coefficient b is 4.
	ySquared.Add(&ySquared, new(fp.Element).SetUint64(4))
	if y.Sqrt(&ySquared) == nil {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV point compressed coordinate")
	}
	if y.LexicographicallyLargest() {
		if masked == cvG1CompressedSmallest {
			y.Neg(&y)
		}
	} else if masked == cvG1CompressedLargest {
		y.Neg(&y)
	}
	point.Y = y
	return point, nil
}

// cvAssertG1SubgroupBatch validates decoded points with one Fiat-Shamir linear
// combination and one order-r check.
func cvAssertG1SubgroupBatch(points []bls12381.G1Affine) error {
	var combined bls12381.G1Affine
	nonInfinity := 0
	for i := range points {
		if !points[i].IsInfinity() {
			nonInfinity++
		}
	}
	if nonInfinity == 0 {
		return nil
	}
	batch := make([]bls12381.G1Affine, 0, nonInfinity)
	statement := make([]byte, 0, nonInfinity*bls12381.SizeOfG1AffineCompressed)
	for i := range points {
		if points[i].IsInfinity() {
			continue
		}
		batch = append(batch, points[i])
		encoded := batch[len(batch)-1].Bytes()
		statement = append(statement, encoded[:]...)
	}
	challenge, err := cvHashToFr(cvSubgroupBatchChallengeDomainScalar, statement)
	if err != nil {
		return err
	}
	if challenge.IsZero() {
		challenge, err = cvHashToFr(cvSubgroupBatchChallengeDomainScalar, statement, []byte("nonzero"))
		if err != nil {
			return err
		}
		if challenge.IsZero() {
			return fmt.Errorf("zero CV subgroup batch challenge")
		}
	}
	weights := cvFrPowers(challenge, nonInfinity)
	result, err := cvG1LinearCombination(batch, weights)
	if err != nil {
		return err
	}
	combined = result
	if !combined.IsInSubGroup() {
		return fmt.Errorf("decoded CV point failed batch subgroup check")
	}
	return nil
}

const cvSubgroupBatchChallengeDomainScalar = "CV-V2-SUBGROUP-BATCH-v1"

func (r *cvWireReader) pointDeferred() (bls12381.G1Affine, error) {
	encoded := r.scratch[:bls12381.SizeOfG1AffineCompressed]
	if _, err := io.ReadFull(r.reader, encoded); err != nil {
		return bls12381.G1Affine{}, err
	}
	point, ok := r.side.consumeHint(encoded)
	if !ok {
		var err error
		point, err = cvDecodeG1WireUnchecked(encoded)
		if err != nil {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS canonical point: %w", err)
		}
	}
	if r.side != nil && r.side.record != nil {
		r.side.record = cvAppendG1HintUncompressed(r.side.record, &point)
	}
	r.deferredPoints = append(r.deferredPoints, point)
	return point, nil
}

func (r *cvWireReader) ciphertextDeferred() (cvElGamalCiphertext, error) {
	first, err := r.pointDeferred()
	if err != nil {
		return cvElGamalCiphertext{}, err
	}
	second, err := r.pointDeferred()
	if err != nil {
		return cvElGamalCiphertext{}, err
	}
	return cvElGamalCiphertext{r: first, c: second}, nil
}

// assertDecodedSubgroup completes deferred subgroup validation for the reader.
func (r *cvWireReader) assertDecodedSubgroup() error {
	if len(r.deferredPoints) == 0 {
		return nil
	}
	if r.side != nil && r.side.collectSubgroup {
		r.side.deferredBatch = append(r.side.deferredBatch, r.deferredPoints...)
		r.deferredPoints = r.deferredPoints[:0]
		return nil
	}
	if err := cvAssertG1SubgroupBatch(r.deferredPoints); err != nil {
		return err
	}
	r.deferredPoints = r.deferredPoints[:0]
	return nil
}
