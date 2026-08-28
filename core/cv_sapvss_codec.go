package core

import (
	"bytes"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvMaxLeafProofWireBytes = 64 << 20
	cvMaxLeafWireBytes      = 64 << 20
)

func (r *cvWireReader) scalar() (fr.Element, error) {
	var encoded [fr.Bytes]byte
	if _, err := io.ReadFull(r.reader, encoded[:]); err != nil {
		return fr.Element{}, err
	}
	var scalar fr.Element
	if err := scalar.SetBytesCanonical(encoded[:]); err != nil {
		return fr.Element{}, fmt.Errorf("invalid CV-sAPVSS canonical scalar: %w", err)
	}
	return scalar, nil
}

func cvCheckedProduct(left, right int, field string) (int, error) {
	if left < 0 || right < 0 || (left != 0 && right > int(^uint(0)>>1)/left) {
		return 0, fmt.Errorf("invalid CV-sAPVSS %s size", field)
	}
	return left * right, nil
}

func cvCheckedAdd(left, right int, field string) (int, error) {
	if left < 0 || right < 0 || right > int(^uint(0)>>1)-left {
		return 0, fmt.Errorf("invalid CV-sAPVSS %s size", field)
	}
	return left + right, nil
}

func cvCountedVectorWireSize(count, width int, field string) (int, error) {
	payload, err := cvCheckedProduct(count, width, field)
	if err != nil {
		return 0, err
	}
	return cvCheckedAdd(4, payload, field)
}

func cvLeafProofWireSize(context *cvLeafContext) (int, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return 0, err
	}
	if context.proofProfile != cvLeafGrothProofProfile {
		return 0, fmt.Errorf("CV-sAPVSS Leaf proof is not enabled by the context")
	}
	receivers := len(context.receiverPublicKeys)
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return 0, err
	}
	receiversPlusOne, err := cvCheckedAdd(receivers, 1, "chunk D")
	if err != nil {
		return 0, err
	}
	wantBits, err := cvCheckedProduct(receivers, chunks, "exact range proof")
	if err != nil {
		return 0, err
	}
	wantBits, err = cvCheckedProduct(wantBits, int(context.profile.chunkBits), "exact range proof")
	if err != nil {
		return 0, err
	}

	pointVector := func(count int, field string) (int, error) {
		return cvCountedVectorWireSize(count, bls12381.SizeOfG1AffineCompressed, field)
	}
	scalarVector := func(count int, field string) (int, error) {
		return cvCountedVectorWireSize(count, fr.Bytes, field)
	}
	total := 0
	add := func(size int, field string) error {
		var addErr error
		total, addErr = cvCheckedAdd(total, size, field)
		return addErr
	}
	addProduct := func(count, width int, field string) error {
		size, productErr := cvCheckedProduct(count, width, field)
		if productErr != nil {
			return productErr
		}
		return add(size, field)
	}
	addVector := func(count, width int, field string) error {
		size, vectorErr := cvCountedVectorWireSize(count, width, field)
		if vectorErr != nil {
			return vectorErr
		}
		return add(size, field)
	}

	if err := addProduct(6, bls12381.SizeOfG1AffineCompressed, "Leaf proof points"); err != nil {
		return 0, err
	}
	if err := addProduct(4, fr.Bytes, "Leaf sharing scalars"); err != nil {
		return 0, err
	}
	for _, vector := range []struct {
		count int
		width int
		field string
	}{
		{cvChunkProofRepetitions, bls12381.SizeOfG1AffineCompressed, "chunk B"},
		{cvChunkProofRepetitions, bls12381.SizeOfG1AffineCompressed, "chunk C"},
		{receiversPlusOne, bls12381.SizeOfG1AffineCompressed, "chunk D"},
	} {
		if err := addVector(vector.count, vector.width, vector.field); err != nil {
			return 0, err
		}
	}
	if err := add(bls12381.SizeOfG1AffineCompressed, "chunk Y"); err != nil {
		return 0, err
	}
	if err := addVector(receivers, fr.Bytes, "chunk coin responses"); err != nil {
		return 0, err
	}
	if err := addVector(cvChunkProofRepetitions, fr.Bytes, "chunk digit responses"); err != nil {
		return 0, err
	}
	if err := add(fr.Bytes, "chunk beta response"); err != nil {
		return 0, err
	}
	if err := addVector(wantBits, bls12381.SizeOfG1AffineCompressed, "exact range commitments"); err != nil {
		return 0, err
	}
	const bitProofWireBytes = 2*bls12381.SizeOfG1AffineCompressed + 3*fr.Bytes
	if err := addVector(wantBits, bitProofWireBytes, "exact range bit proofs"); err != nil {
		return 0, err
	}

	pointResponses, err := pointVector(receivers, "exact range link points")
	if err != nil {
		return 0, err
	}
	scalarResponses, err := scalarVector(receivers, "exact range link scalars")
	if err != nil {
		return 0, err
	}
	linkSize := 0
	for _, size := range []int{
		bls12381.SizeOfG1AffineCompressed,
		pointResponses,
		pointResponses,
		fr.Bytes,
		scalarResponses,
		scalarResponses,
	} {
		linkSize, err = cvCheckedAdd(linkSize, size, "exact range link")
		if err != nil {
			return 0, err
		}
	}
	linksPayload, err := cvCheckedProduct(chunks, linkSize, "exact range links")
	if err != nil {
		return 0, err
	}
	linksSize, err := cvCheckedAdd(4, linksPayload, "exact range links")
	if err != nil {
		return 0, err
	}
	if err := add(linksSize, "exact range links"); err != nil {
		return 0, err
	}
	return total, nil
}

func cvLeafWireSize(context *cvLeafContext) (int, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return 0, err
	}
	if context.proofProfile == cvLeafFullCompactProofProfile ||
		context.proofProfile == cvLeafFullFieldProofProfile {
		return 0, fmt.Errorf("CV-sAPVSS full compact Leaf proof has variable canonical size")
	}
	contextWire, err := cvLeafContextCanonicalBytes(context)
	if err != nil {
		return 0, err
	}
	receivers := len(context.receiverPublicKeys)
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return 0, err
	}
	commitments, err := cvCheckedAdd(context.sharingDegree, 1, "Leaf coefficient commitments")
	if err != nil {
		return 0, err
	}
	ciphertexts := chunks
	if context.proofProfile != cvLeafStructuralProofProfile {
		ciphertexts, err = cvCheckedAdd(ciphertexts, 1, "Leaf receiver ciphertexts")
		if err != nil {
			return 0, err
		}
	}
	ciphertextBytes, err := cvCheckedProduct(ciphertexts, 2*bls12381.SizeOfG1AffineCompressed, "Leaf receiver ciphertexts")
	if err != nil {
		return 0, err
	}
	receiverSize, err := cvCheckedAdd(4+3*bls12381.SizeOfG1AffineCompressed+4, ciphertextBytes, "Leaf receiver")
	if err != nil {
		return 0, err
	}
	receiverPayload, err := cvCheckedProduct(receivers, receiverSize, "Leaf receivers")
	if err != nil {
		return 0, err
	}
	receiverVector, err := cvCheckedAdd(4, receiverPayload, "Leaf receivers")
	if err != nil {
		return 0, err
	}
	commitmentVector, err := cvCountedVectorWireSize(commitments, bls12381.SizeOfG1AffineCompressed, "Leaf coefficient commitments")
	if err != nil {
		return 0, err
	}
	contextField, err := cvCheckedAdd(4, len(contextWire), "Leaf context")
	if err != nil {
		return 0, err
	}
	total := 0
	for _, size := range []int{contextField, 8, commitmentVector, receiverVector, 1} {
		total, err = cvCheckedAdd(total, size, "Leaf")
		if err != nil {
			return 0, err
		}
	}
	if context.proofProfile == cvLeafGrothProofProfile {
		proofSize, proofErr := cvLeafProofWireSize(context)
		if proofErr != nil {
			return 0, proofErr
		}
		proofField, proofErr := cvCheckedAdd(4, proofSize, "Leaf proof")
		if proofErr != nil {
			return 0, proofErr
		}
		total, err = cvCheckedAdd(total, proofField, "Leaf")
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func cvReadExactBytes(r *cvWireReader, expected int, field string) ([]byte, error) {
	value, err := r.bytes(expected)
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS %s: %w", field, err)
	}
	if len(value) != expected {
		return nil, fmt.Errorf("invalid CV-sAPVSS %s length: got %d, want %d", field, len(value), expected)
	}
	return value, nil
}

func cvRequireRemaining(r *cvWireReader, count, width int, field string) error {
	required, err := cvCheckedProduct(count, width, field)
	if err != nil {
		return err
	}
	if required > r.reader.Len() {
		return fmt.Errorf("CV-sAPVSS %s exceeds remaining wire", field)
	}
	return nil
}

func cvReadExactCount(r *cvWireReader, expected int, field string) error {
	count, err := r.uint32()
	if err != nil {
		return fmt.Errorf("decode CV-sAPVSS %s count: %w", field, err)
	}
	if expected < 0 || count != expected {
		return fmt.Errorf("invalid CV-sAPVSS %s count: got %d, want %d", field, count, expected)
	}
	return nil
}

func cvReadExactPointVector(r *cvWireReader, expected int, field string) ([]bls12381.G1Affine, error) {
	if err := cvReadExactCount(r, expected, field); err != nil {
		return nil, err
	}
	if err := cvRequireRemaining(r, expected, bls12381.SizeOfG1AffineCompressed, field); err != nil {
		return nil, err
	}
	points := make([]bls12381.G1Affine, expected)
	for i := range points {
		point, err := r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS %s point %d: %w", field, i, err)
		}
		points[i] = point
	}
	return points, nil
}

func cvReadExactPointVectorDeferred(r *cvWireReader, expected int, field string) ([]bls12381.G1Affine, error) {
	if err := cvReadExactCount(r, expected, field); err != nil {
		return nil, err
	}
	if err := cvRequireRemaining(r, expected, bls12381.SizeOfG1AffineCompressed, field); err != nil {
		return nil, err
	}
	points := make([]bls12381.G1Affine, expected)
	for i := range points {
		point, err := r.pointDeferred()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS %s point %d: %w", field, i, err)
		}
		points[i] = point
	}
	return points, nil
}

func cvReadExactScalarVector(r *cvWireReader, expected int, field string) ([]fr.Element, error) {
	if err := cvReadExactCount(r, expected, field); err != nil {
		return nil, err
	}
	if err := cvRequireRemaining(r, expected, fr.Bytes, field); err != nil {
		return nil, err
	}
	scalars := make([]fr.Element, expected)
	for i := range scalars {
		scalar, err := r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS %s scalar %d: %w", field, i, err)
		}
		scalars[i] = scalar
	}
	return scalars, nil
}

func cvDecodeLeafProof(wire []byte, expectedContext *cvLeafContext) (*cvLeafProof, error) {
	if err := cvValidateLeafContext(expectedContext); err != nil {
		return nil, err
	}
	if expectedContext.proofProfile != cvLeafGrothProofProfile {
		return nil, fmt.Errorf("CV-sAPVSS Leaf proof is not enabled by the expected context")
	}
	expectedWireSize, err := cvLeafProofWireSize(expectedContext)
	if err != nil {
		return nil, err
	}
	if expectedWireSize > cvMaxLeafProofWireBytes {
		return nil, fmt.Errorf("CV-sAPVSS Leaf proof exceeds the wire safety limit")
	}
	if len(wire) != expectedWireSize {
		return nil, fmt.Errorf("invalid CV-sAPVSS Leaf proof length: got %d, want %d", len(wire), expectedWireSize)
	}
	receivers := len(expectedContext.receiverPublicKeys)
	chunks, err := cvChunkCount(expectedContext.profile)
	if err != nil {
		return nil, err
	}
	wantBits, err := cvCheckedProduct(receivers, chunks, "exact range proof")
	if err != nil {
		return nil, err
	}
	wantBits, err = cvCheckedProduct(wantBits, int(expectedContext.profile.chunkBits), "exact range proof")
	if err != nil {
		return nil, err
	}

	r := newCVWireReader(wire)
	proof := &cvLeafProof{}
	for i, point := range []*bls12381.G1Affine{
		&proof.sharing.fScalar,
		&proof.sharing.fBlinding,
		&proof.sharing.a,
		&proof.sharing.yScalar,
		&proof.sharing.yBlinding,
		&proof.chunking.y0,
	} {
		decoded, pointErr := r.point()
		if pointErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS Leaf proof point %d: %w", i, pointErr)
		}
		*point = decoded
	}
	for i, scalar := range []*fr.Element{
		&proof.sharing.zScalar,
		&proof.sharing.zBlinding,
		&proof.sharing.zScalarCoin,
		&proof.sharing.zBlindingCoin,
	} {
		decoded, scalarErr := r.scalar()
		if scalarErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS Leaf sharing scalar %d: %w", i, scalarErr)
		}
		*scalar = decoded
	}
	proof.chunking.b, err = cvReadExactPointVector(r, cvChunkProofRepetitions, "chunk B")
	if err != nil {
		return nil, err
	}
	proof.chunking.c, err = cvReadExactPointVector(r, cvChunkProofRepetitions, "chunk C")
	if err != nil {
		return nil, err
	}
	proof.chunking.d, err = cvReadExactPointVector(r, receivers+1, "chunk D")
	if err != nil {
		return nil, err
	}
	proof.chunking.y, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS chunk Y: %w", err)
	}
	proof.chunking.zCoins, err = cvReadExactScalarVector(r, receivers, "chunk coin responses")
	if err != nil {
		return nil, err
	}
	proof.chunking.zDigits, err = cvReadExactScalarVector(r, cvChunkProofRepetitions, "chunk digit responses")
	if err != nil {
		return nil, err
	}
	proof.chunking.zBeta, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS chunk beta response: %w", err)
	}

	rangeProof := &proof.chunking.exactRange
	rangeProof.commitments, err = cvReadExactPointVector(r, wantBits, "exact range commitments")
	if err != nil {
		return nil, err
	}
	if err := cvReadExactCount(r, wantBits, "exact range bit proofs"); err != nil {
		return nil, err
	}
	const bitProofWireBytes = 2*bls12381.SizeOfG1AffineCompressed + 3*fr.Bytes
	if err := cvRequireRemaining(r, wantBits, bitProofWireBytes, "exact range bit proofs"); err != nil {
		return nil, err
	}
	rangeProof.bits = make([]cvBitProof, wantBits)
	for i := range rangeProof.bits {
		bit := &rangeProof.bits[i]
		bit.t0, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range T0 %d: %w", i, err)
		}
		bit.t1, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range T1 %d: %w", i, err)
		}
		bit.e0, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range E0 %d: %w", i, err)
		}
		bit.z0, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range Z0 %d: %w", i, err)
		}
		bit.z1, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range Z1 %d: %w", i, err)
		}
	}
	if err := cvReadExactCount(r, chunks, "exact range links"); err != nil {
		return nil, err
	}
	rangeProof.links = make([]cvRangeLinkProof, chunks)
	for i := range rangeProof.links {
		link := &rangeProof.links[i]
		link.tCoin, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range coin link %d: %w", i, err)
		}
		link.tCommitments, err = cvReadExactPointVector(r, receivers, "exact range link commitments")
		if err != nil {
			return nil, err
		}
		link.tCiphertexts, err = cvReadExactPointVector(r, receivers, "exact range link ciphertexts")
		if err != nil {
			return nil, err
		}
		link.zCoin, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range coin response %d: %w", i, err)
		}
		link.zDigits, err = cvReadExactScalarVector(r, receivers, "exact range link digit responses")
		if err != nil {
			return nil, err
		}
		link.zRhos, err = cvReadExactScalarVector(r, receivers, "exact range link rho responses")
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS Leaf proof bytes")
	}
	canonical, err := cvLeafProofCanonicalBytes(proof)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS Leaf proof encoding")
	}
	return proof, nil
}

func cvDecodeLeaf(wire []byte, expectedContext *cvLeafContext) (*cvLeaf, error) {
	if err := cvValidateLeafContext(expectedContext); err != nil {
		return nil, err
	}
	if expectedContext.proofProfile == cvLeafFullCompactProofProfile ||
		expectedContext.proofProfile == cvLeafFullFieldProofProfile {
		if len(wire) == 0 || len(wire) > cvMaxLeafWireBytes {
			return nil, fmt.Errorf("invalid CV-sAPVSS full compact Leaf length")
		}
	} else {
		expectedWireSize, err := cvLeafWireSize(expectedContext)
		if err != nil {
			return nil, err
		}
		if expectedWireSize > cvMaxLeafWireBytes {
			return nil, fmt.Errorf("CV-sAPVSS Leaf exceeds the wire safety limit")
		}
		if len(wire) != expectedWireSize {
			return nil, fmt.Errorf("invalid CV-sAPVSS Leaf length: got %d, want %d", len(wire), expectedWireSize)
		}
	}
	expectedContextWire, err := cvLeafContextCanonicalBytes(expectedContext)
	if err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	contextWire, err := cvReadExactBytes(r, len(expectedContextWire), "Leaf context")
	if err != nil || !bytes.Equal(contextWire, expectedContextWire) {
		return nil, fmt.Errorf("CV-sAPVSS Leaf context mismatch")
	}
	context, err := cvDecodeLeafContext(contextWire)
	if err != nil {
		return nil, err
	}
	leaf := &cvLeaf{context: context}
	leaf.dealerID, err = r.uint64()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS Leaf dealer: %w", err)
	}
	leaf.coefficientCommitments, err = cvReadExactPointVector(
		r,
		expectedContext.sharingDegree+1,
		"Leaf coefficient commitments",
	)
	if err != nil {
		return nil, err
	}
	receivers := len(expectedContext.receiverPublicKeys)
	if err := cvReadExactCount(r, receivers, "Leaf receivers"); err != nil {
		return nil, err
	}
	chunks, err := cvChunkCount(expectedContext.profile)
	if err != nil {
		return nil, err
	}
	ciphertextCount := chunks
	if expectedContext.proofProfile != cvLeafStructuralProofProfile {
		ciphertextCount++
	}
	ciphertextBytes, err := cvCheckedProduct(ciphertextCount, 2*bls12381.SizeOfG1AffineCompressed, "Leaf receiver ciphertexts")
	if err != nil {
		return nil, err
	}
	receiverBytes := 4 + 3*bls12381.SizeOfG1AffineCompressed + 4 + ciphertextBytes
	if err := cvRequireRemaining(r, receivers, receiverBytes, "Leaf receivers"); err != nil {
		return nil, err
	}
	leaf.receivers = make([]cvLeafReceiver, receivers)
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		receiver.receiverIndex, err = r.uint32()
		if err != nil || receiver.receiverIndex != i+1 {
			return nil, fmt.Errorf("invalid CV-sAPVSS Leaf receiver index %d", i+1)
		}
		receiver.receiverPublicKey, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS Leaf receiver key %d: %w", i+1, err)
		}
		share := &cvEncryptedShare{}
		share.receiverPublicKey, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS Leaf encrypted key %d: %w", i+1, err)
		}
		share.commitment, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS Leaf commitment %d: %w", i+1, err)
		}
		if err := cvReadExactCount(r, chunks, "Leaf scalar chunks"); err != nil {
			return nil, err
		}
		if err := cvRequireRemaining(r, ciphertextCount, 2*bls12381.SizeOfG1AffineCompressed, "Leaf ciphertexts"); err != nil {
			return nil, err
		}
		share.scalarChunks = make([]cvElGamalCiphertext, chunks)
		for j := range share.scalarChunks {
			share.scalarChunks[j], err = r.ciphertext()
			if err != nil {
				return nil, fmt.Errorf("decode CV-sAPVSS Leaf ciphertext %d/%d: %w", i+1, j, err)
			}
		}
		if expectedContext.proofProfile != cvLeafStructuralProofProfile {
			share.blinding, err = r.ciphertext()
			if err != nil {
				return nil, fmt.Errorf("decode CV-sAPVSS Leaf blinding ciphertext %d: %w", i+1, err)
			}
		}
		receiver.encryptedShare = share
	}
	capability, err := r.reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS Leaf proof capability: %w", err)
	}
	switch expectedContext.proofProfile {
	case cvLeafStructuralProofProfile:
		if capability != 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS structural Leaf capability")
		}
	case cvLeafGrothProofProfile:
		if capability != 1 {
			return nil, fmt.Errorf("missing CV-sAPVSS Leaf proof")
		}
		proofSize, proofErr := cvLeafProofWireSize(expectedContext)
		if proofErr != nil {
			return nil, proofErr
		}
		proofWire, proofErr := cvReadExactBytes(r, proofSize, "Leaf proof")
		if proofErr != nil {
			return nil, proofErr
		}
		leaf.proof, proofErr = cvDecodeLeafProof(proofWire, expectedContext)
		if proofErr != nil {
			return nil, proofErr
		}
		leaf.hasLeafNIZK = true
	case cvLeafFullCompactProofProfile:
		if capability != 2 {
			return nil, fmt.Errorf("missing CV-sAPVSS full compact proof")
		}
		proofWire, proofErr := r.bytes(cvMaxLeafProofWireBytes)
		if proofErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS full compact proof: %w", proofErr)
		}
		if len(proofWire) == 0 {
			return nil, fmt.Errorf("empty CV-sAPVSS full compact proof")
		}
		leaf.hasLeafNIZK = true
		leaf.compactProof, proofErr = apvssDecodeCompactFallbackProofWithVerify(
			proofWire, leaf, false,
		)
		if proofErr != nil {
			return nil, proofErr
		}
	case cvLeafFullFieldProofProfile:
		if capability != 3 {
			return nil, fmt.Errorf("missing CV-sAPVSS field-congruent proof")
		}
		proofWire, proofErr := r.bytes(cvMaxLeafProofWireBytes)
		if proofErr != nil || len(proofWire) == 0 {
			return nil, fmt.Errorf("decode CV-sAPVSS field-congruent proof: %w", proofErr)
		}
		leaf.hasLeafNIZK = true
		leaf.compactProof, proofErr = apvssDecodeCompactFieldProofWithVerify(
			proofWire, leaf, false,
		)
		if proofErr != nil {
			return nil, proofErr
		}
	default:
		return nil, fmt.Errorf("unsupported CV-sAPVSS Leaf proof profile")
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS Leaf bytes")
	}
	leaf.digest = hashBytes([]byte(cvLeafDigestDomain), wire)
	canonical, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS Leaf encoding")
	}
	if err := cvVerifyLeafCanonical(expectedContext, expectedContextWire, contextWire, leaf, wire); err != nil {
		return nil, err
	}
	return leaf, nil
}

func cvDecodeReceipt(
	wire []byte,
	expectedContext *cvLeafContext,
	agg *cvAggregateTranscript,
	expectedReceiverIndex int,
) (*cvReceipt, error) {
	return cvDecodeReceiptMode(wire, expectedContext, agg, expectedReceiverIndex, true)
}

func cvDecodeReceiptVerifiedAggregate(
	wire []byte,
	expectedContext *cvLeafContext,
	agg *cvAggregateTranscript,
	expectedReceiverIndex int,
) (*cvReceipt, error) {
	return cvDecodeReceiptMode(wire, expectedContext, agg, expectedReceiverIndex, false)
}

func cvDecodeReceiptMode(
	wire []byte,
	expectedContext *cvLeafContext,
	agg *cvAggregateTranscript,
	expectedReceiverIndex int,
	checkAggregateDigest bool,
) (*cvReceipt, error) {
	if len(wire) == 0 || len(wire) > cvMaxCanonicalFieldBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt length")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvReceiptDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiptDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt domain")
	}
	receipt := &cvReceipt{}
	receipt.aggregateDigest, err = r.bytes(32)
	if err != nil || len(receipt.aggregateDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt aggregate digest")
	}
	receipt.receiverIndex, err = r.uint32()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS receipt receiver index: %w", err)
	}
	modeValue, err := r.uint32()
	if err != nil || (modeValue != 0 && modeValue != 1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt mode")
	}
	receipt.proof.feldman = modeValue == 1
	points := []*bls12381.G1Affine{&receipt.publicScalar, &receipt.proof.tKey, &receipt.proof.tScalar}
	if !receipt.proof.feldman {
		points = []*bls12381.G1Affine{
			&receipt.publicScalar,
			&receipt.blindingOpening,
			&receipt.proof.tKey,
			&receipt.proof.tScalar,
			&receipt.proof.tBlinding,
		}
	}
	for i, point := range points {
		decoded, pointErr := r.point()
		if pointErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS receipt point %d: %w", i, pointErr)
		}
		*point = decoded
	}
	receipt.proof.z, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS receipt response: %w", err)
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS receipt bytes")
	}
	canonical, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS receipt encoding")
	}
	receipt.digestWire = append([]byte(nil), wire...)
	receipt.digest = hashBytes([]byte(cvReceiptDomain), wire)
	if err := cvVerifyShareMode(expectedContext, agg, expectedReceiverIndex, receipt, checkAggregateDigest); err != nil {
		return nil, err
	}
	return receipt, nil
}
