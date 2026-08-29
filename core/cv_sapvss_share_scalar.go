package core

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvAggregateShareWireDomainScalar      = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-share"
	cvAggregateShareChallengeDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-share/challenge"
)

type cvAggregateShareProofScalar struct {
	KeyCommitment             bls12381.G1Affine
	ScalarCipherCommitment    bls12381.G1Affine
	ScalarKnowledgeCommitment bls12381.G1Affine
	BlindingDecryptCommitment bls12381.G1Affine
	KeyResponse               fr.Element
	ScalarResponse            fr.Element
}

type cvScalarShareOutputScalar struct {
	AggregateDigest []byte
	ReceiverID      int
	ReceiverIndex   int
	Y               bls12381.G1Affine
	YBlind          bls12381.G1Affine
	Proof           cvAggregateShareProofScalar
}

type cvAggregateShareDecryptionTimingsScalar struct {
	ScalarBoundedDLog       time.Duration
	BlindingGroupDecryption time.Duration
}

func cvDecryptAggregateShareScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, *cvScalarShareOutputScalar, error) {
	scalar, output, _, err := cvDecryptAggregateShareMeasuredScalar(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, receiverSecret,
	)
	return scalar, output, err
}

func cvDecryptAggregateShareMeasuredScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, *cvScalarShareOutputScalar, cvAggregateShareDecryptionTimingsScalar, error) {
	var timings cvAggregateShareDecryptionTimingsScalar
	if err := cvValidateAggregateShareInputsScalar(aggregate, context, params, receiverID, receiverIndex, receiverPublicKey); err != nil {
		return fr.Element{}, nil, timings, err
	}
	wantPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil || !wantPublic.Equal(receiverPublicKey) {
		return fr.Element{}, nil, timings, fmt.Errorf("CV V2 aggregate-share secret does not match receiver key")
	}
	base, digitBound, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return fr.Element{}, nil, timings, err
	}
	receiver := &aggregate.Receivers[receiverIndex-1]
	digits := make([]uint64, chunks)
	started := time.Now()
	solver := cvNewBoundedDLogSolverForBaseScalar(&genG1, digitBound)
	timings.ScalarBoundedDLog += time.Since(started)
	for chunk := 0; chunk < chunks; chunk++ {
		plaintext := cvDecryptGroupCiphertextScalar(&receiver.ScalarChunks[chunk], receiverSecret)
		started = time.Now()
		digit, ok := solver.solve(&plaintext)
		timings.ScalarBoundedDLog += time.Since(started)
		if !ok {
			return fr.Element{}, nil, timings, fmt.Errorf("CV V2 aggregate scalar chunk %d is outside [0,K(B-1)]", chunk)
		}
		digits[chunk] = digit
	}
	scalar, err := cvAggregateDigitsToScalarScalar(digits, context.Profile.chunkBits, base, digitBound)
	if err != nil {
		return fr.Element{}, nil, timings, err
	}
	started = time.Now()
	yBlind := cvDecryptGroupCiphertextScalar(&receiver.Blinding, receiverSecret)
	timings.BlindingGroupDecryption += time.Since(started)
	output := &cvScalarShareOutputScalar{
		AggregateDigest: append([]byte(nil), aggregate.Digest...), ReceiverID: receiverID, ReceiverIndex: receiverIndex,
		Y: cvPointTimes(&genG1, &scalar), YBlind: yBlind,
	}
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return fr.Element{}, nil, timings, fmt.Errorf("CV V2 aggregate decrypted shares do not open receiver evaluation")
	}
	proof, err := cvProveAggregateShareScalar(aggregate, context, receiverPublicKey, receiverSecret, scalar, output)
	if err != nil {
		return fr.Element{}, nil, timings, err
	}
	output.Proof = *proof
	if err := cvVerifyAggregateShareAfterValidationScalar(
		output, aggregate, context, params, receiverPublicKey,
	); err != nil {
		return fr.Element{}, nil, timings, err
	}
	return scalar, output, timings, nil
}

func cvProveAggregateShareScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, receiverPublicKey *bls12381.G1Affine,
	receiverSecret, scalar fr.Element, output *cvScalarShareOutputScalar,
) (*cvAggregateShareProofScalar, error) {
	weighted, err := cvWeightedAggregateScalarScalar(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return nil, err
	}
	var keyNonce, scalarNonce fr.Element
	if _, err := keyNonce.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := scalarNonce.SetRandom(); err != nil {
		return nil, err
	}
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	proof := &cvAggregateShareProofScalar{
		KeyCommitment: cvPointTimes(&genG1, &keyNonce),
		ScalarCipherCommitment: cvPointSum(
			pointPtr(cvPointTimes(&weighted.r, &keyNonce)), pointPtr(cvPointTimes(&genG1, &scalarNonce)),
		),
		ScalarKnowledgeCommitment: cvPointTimes(&genG1, &scalarNonce),
		BlindingDecryptCommitment: cvPointTimes(&receiver.Blinding.r, &keyNonce),
	}
	challenge, err := cvAggregateShareChallengeScalar(aggregate, context, receiverPublicKey, output, proof)
	if err != nil {
		return nil, err
	}
	proof.KeyResponse.Mul(&challenge, &receiverSecret).Add(&proof.KeyResponse, &keyNonce)
	proof.ScalarResponse.Mul(&challenge, &scalar).Add(&proof.ScalarResponse, &scalarNonce)
	return proof, nil
}

func cvVerifyAggregateShareScalar(
	output *cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeScalar(output, aggregate, context, params, receiverPublicKey, true, true)
}

func cvVerifyAggregateShareAfterPointDecodingScalar(
	output *cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeScalar(output, aggregate, context, params, receiverPublicKey, false, false)
}

func cvVerifyAggregateShareAfterValidationScalar(
	output *cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeScalar(output, aggregate, context, params, receiverPublicKey, false, false)
}

func cvVerifyAggregateShareModeScalar(
	output *cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receiverPublicKey *bls12381.G1Affine, validatePoints, validateAggregate bool,
) error {
	var aggregateErr error
	if validateAggregate {
		aggregateErr = cvValidateAggregateShareInputsScalar(
			aggregate, context, params, outputReceiverIDScalar(output), outputReceiverIndexScalar(output), receiverPublicKey,
		)
	} else {
		aggregateErr = cvValidateAggregateShareInputsAfterValidationScalar(
			aggregate, context, params, outputReceiverIDScalar(output), outputReceiverIndexScalar(output), receiverPublicKey,
		)
	}
	if output == nil || aggregate == nil || output.ReceiverID < 0 || output.ReceiverIndex <= 0 || len(output.AggregateDigest) != 32 ||
		!bytes.Equal(output.AggregateDigest, aggregate.Digest) ||
		aggregateErr != nil || (validatePoints && (!cvValidG1(&output.Y, true) ||
		!cvValidG1(&output.YBlind, true) || !cvValidAggregateShareProofScalar(&output.Proof))) {
		return fmt.Errorf("invalid CV V2 aggregate-share output")
	}
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return fmt.Errorf("CV V2 aggregate-share opening mismatch")
	}
	weighted, err := cvWeightedAggregateScalarScalar(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return err
	}
	challenge, err := cvAggregateShareChallengeScalar(aggregate, context, receiverPublicKey, output, &output.Proof)
	if err != nil {
		return err
	}
	left := cvPointTimes(&genG1, &output.Proof.KeyResponse)
	right := cvPointSum(&output.Proof.KeyCommitment, pointPtr(cvPointTimes(receiverPublicKey, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid CV V2 aggregate-share key equation")
	}
	left = cvPointSum(
		pointPtr(cvPointTimes(&weighted.r, &output.Proof.KeyResponse)),
		pointPtr(cvPointTimes(&genG1, &output.Proof.ScalarResponse)),
	)
	right = cvPointSum(&output.Proof.ScalarCipherCommitment,
		pointPtr(cvPointTimes(&weighted.c, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid CV V2 aggregate-share scalar ciphertext equation")
	}
	left = cvPointTimes(&genG1, &output.Proof.ScalarResponse)
	right = cvPointSum(&output.Proof.ScalarKnowledgeCommitment,
		pointPtr(cvPointTimes(&output.Y, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid CV V2 aggregate-share scalar knowledge equation")
	}
	var blindingTarget bls12381.G1Affine
	blindingTarget.Sub(&receiver.Blinding.c, &output.YBlind)
	left = cvPointTimes(&receiver.Blinding.r, &output.Proof.KeyResponse)
	right = cvPointSum(&output.Proof.BlindingDecryptCommitment,
		pointPtr(cvPointTimes(&blindingTarget, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid CV V2 aggregate-share blinding decryption equation")
	}
	return nil
}

func outputReceiverIDScalar(output *cvScalarShareOutputScalar) int {
	if output == nil {
		return -1
	}
	return output.ReceiverID
}

func outputReceiverIndexScalar(output *cvScalarShareOutputScalar) int {
	if output == nil {
		return -1
	}
	return output.ReceiverIndex
}

func cvAggregateShareChallengeScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, receiverPublicKey *bls12381.G1Affine,
	output *cvScalarShareOutputScalar, proof *cvAggregateShareProofScalar,
) (fr.Element, error) {
	if aggregate == nil || context == nil || output == nil || proof == nil ||
		output.ReceiverIndex <= 0 || output.ReceiverIndex > len(aggregate.Receivers) ||
		!cvValidG1(receiverPublicKey, false) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 aggregate-share challenge")
	}
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return fr.Element{}, err
	}
	weighted, err := cvWeightedAggregateScalarScalar(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return fr.Element{}, err
	}
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextWire)
	_ = cvWriteBytes(&wire, aggregate.Digest)
	cvWriteUint64(&wire, uint64(output.ReceiverID))
	cvWriteUint64(&wire, uint64(output.ReceiverIndex))
	cvWritePoint(&wire, receiverPublicKey)
	cvWriteCiphertext(&wire, &weighted)
	cvWriteCiphertext(&wire, &receiver.Blinding)
	cvWritePoint(&wire, &output.Y)
	cvWritePoint(&wire, &output.YBlind)
	for _, point := range []*bls12381.G1Affine{
		&proof.KeyCommitment, &proof.ScalarCipherCommitment,
		&proof.ScalarKnowledgeCommitment, &proof.BlindingDecryptCommitment,
	} {
		cvWritePoint(&wire, point)
	}
	return cvHashToFr(cvAggregateShareChallengeDomainScalar, wire.Bytes())
}

func cvWeightedAggregateScalarScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, receiverIndex int,
) (cvElGamalCiphertext, error) {
	var weighted cvElGamalCiphertext
	if aggregate == nil || context == nil || receiverIndex <= 0 || receiverIndex > len(aggregate.Receivers) {
		return weighted, fmt.Errorf("invalid CV V2 weighted aggregate scalar")
	}
	base, _, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return weighted, err
	}
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	receiver := &aggregate.Receivers[receiverIndex-1]
	if len(receiver.ScalarChunks) != chunks {
		return weighted, fmt.Errorf("invalid CV V2 weighted aggregate scalar length")
	}
	for chunk := 0; chunk < chunks; chunk++ {
		weighted.r.Add(&weighted.r, pointPtr(cvPointTimes(&receiver.ScalarChunks[chunk].r, &powers[chunk])))
		weighted.c.Add(&weighted.c, pointPtr(cvPointTimes(&receiver.ScalarChunks[chunk].c, &powers[chunk])))
	}
	return weighted, nil
}

func cvAggregateDigitsToScalarScalar(digits []uint64, chunkBits uint, base, bound uint64) (fr.Element, error) {
	if len(digits) == 0 || chunkBits == 0 || chunkBits > cvMaxChunkBits || base != uint64(1)<<chunkBits {
		return fr.Element{}, fmt.Errorf("invalid CV V2 aggregate digit reconstruction")
	}
	value := new(big.Int)
	for index, digit := range digits {
		if digit > bound {
			return fr.Element{}, fmt.Errorf("CV V2 aggregate digit exceeds K(B-1)")
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(index)*chunkBits)
		value.Add(value, term)
	}
	value.Mod(value, fr.Modulus())
	var scalar fr.Element
	scalar.SetBigInt(value)
	return scalar, nil
}

func cvValidateAggregateShareInputsScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvValidateAggregateShareInputsModeScalar(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, true,
	)
}

func cvValidateAggregateShareInputsAfterValidationScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvValidateAggregateShareInputsModeScalar(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, false,
	)
}

func cvValidateAggregateShareInputsModeScalar(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, validateAggregate bool,
) error {
	if context == nil || params.componentCount <= 0 || context.Profile.maxComponents != params.componentCount ||
		context.SharingDegree != params.newShareDegree || params.newShareThreshold != context.SharingDegree+1 ||
		cvValidateReceiverBindingScalar(context, receiverID, receiverIndex, receiverPublicKey) != nil {
		return fmt.Errorf("invalid CV V2 aggregate-share parameters")
	}
	var err error
	if validateAggregate {
		_, err = cvAggregateScalarCanonicalBytes(aggregate, context, params)
	} else {
		_, err = cvAggregateScalarCanonicalBytesAfterValidation(aggregate, context, params)
	}
	if err != nil {
		return err
	}
	receiver := &aggregate.Receivers[receiverIndex-1]
	if receiver.ReceiverID != receiverID || receiver.ReceiverIndex != receiverIndex {
		return fmt.Errorf("CV V2 aggregate-share receiver mismatch")
	}
	return nil
}

func cvValidAggregateShareProofScalar(proof *cvAggregateShareProofScalar) bool {
	if proof == nil {
		return false
	}
	for _, point := range []*bls12381.G1Affine{
		&proof.KeyCommitment, &proof.ScalarCipherCommitment,
		&proof.ScalarKnowledgeCommitment, &proof.BlindingDecryptCommitment,
	} {
		if !cvValidG1(point, true) {
			return false
		}
	}
	return true
}

func cvScalarShareOutputScalarCanonicalBytes(output *cvScalarShareOutputScalar) ([]byte, error) {
	return cvScalarShareOutputScalarCanonicalBytesMode(output, true)
}

func cvScalarShareOutputScalarCanonicalBytesAfterValidation(output *cvScalarShareOutputScalar) ([]byte, error) {
	return cvScalarShareOutputScalarCanonicalBytesMode(output, false)
}

func cvScalarShareOutputScalarCanonicalBytesMode(output *cvScalarShareOutputScalar, validatePoints bool) ([]byte, error) {
	if output == nil || len(output.AggregateDigest) != 32 || output.ReceiverID < 0 || output.ReceiverIndex <= 0 ||
		(validatePoints && (!cvValidG1(&output.Y, true) || !cvValidG1(&output.YBlind, true) ||
			!cvValidAggregateShareProofScalar(&output.Proof))) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateShareWireDomainScalar))
	_ = cvWriteBytes(&wire, output.AggregateDigest)
	cvWriteUint64(&wire, uint64(output.ReceiverID))
	cvWriteUint64(&wire, uint64(output.ReceiverIndex))
	for _, point := range []*bls12381.G1Affine{
		&output.Y, &output.YBlind, &output.Proof.KeyCommitment,
		&output.Proof.ScalarCipherCommitment, &output.Proof.ScalarKnowledgeCommitment,
		&output.Proof.BlindingDecryptCommitment,
	} {
		cvWritePoint(&wire, point)
	}
	cvWriteScalar(&wire, &output.Proof.KeyResponse)
	cvWriteScalar(&wire, &output.Proof.ScalarResponse)
	return wire.Bytes(), nil
}

func cvDecodeScalarShareOutputScalar(
	wire []byte, aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	receivers *cvReceiverKeyMaterialScalar,
) (*cvScalarShareOutputScalar, error) {
	if cvValidateReceiverMaterialForLeafScalar(context, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver registry")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateShareWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share digest")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver ID")
	}
	receiverIndex, err := r.uint64()
	if err != nil || receiverIndex == 0 || receiverIndex > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver index")
	}
	points := make([]bls12381.G1Affine, 6)
	for i := range points {
		points[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 aggregate-share point")
		}
	}
	keyResponse, err := r.scalar()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share key response")
	}
	scalarResponse, err := r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share scalar response")
	}
	output := &cvScalarShareOutputScalar{
		AggregateDigest: digest, ReceiverID: int(receiverID), ReceiverIndex: int(receiverIndex),
		Y: points[0], YBlind: points[1], Proof: cvAggregateShareProofScalar{
			KeyCommitment: points[2], ScalarCipherCommitment: points[3],
			ScalarKnowledgeCommitment: points[4], BlindingDecryptCommitment: points[5],
			KeyResponse: keyResponse, ScalarResponse: scalarResponse,
		},
	}
	canonical, err := cvScalarShareOutputScalarCanonicalBytesAfterValidation(output)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate-share output")
	}
	index := output.ReceiverIndex - 1
	if index < 0 || index >= len(receivers.encryptionPublicKeys) {
		return nil, fmt.Errorf("CV V2 aggregate-share receiver is outside registry")
	}
	if err := cvVerifyAggregateShareAfterPointDecodingScalar(
		output, aggregate, context, params, &receivers.encryptionPublicKeys[index],
	); err != nil {
		return nil, err
	}
	return output, nil
}

func cvRecoverThresholdPublicKeyScalar(
	outputs []*cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receivers *cvReceiverKeyMaterialScalar,
) (bls12381.G1Affine, error) {
	return cvRecoverThresholdPublicKeyModeScalar(outputs, aggregate, context, params, receivers, true)
}

func cvRecoverThresholdPublicKeyAfterValidationScalar(
	outputs []*cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receivers *cvReceiverKeyMaterialScalar,
) (bls12381.G1Affine, error) {
	return cvRecoverThresholdPublicKeyModeScalar(outputs, aggregate, context, params, receivers, false)
}

func cvRecoverThresholdPublicKeyModeScalar(
	outputs []*cvScalarShareOutputScalar, aggregate *cvAggregateScalar, context *cvLeafContextScalar,
	params cvScalarParams, receivers *cvReceiverKeyMaterialScalar, validateOutputs bool,
) (bls12381.G1Affine, error) {
	if cvValidateReceiverMaterialForLeafScalar(context, receivers) != nil || len(outputs) < params.newShareThreshold {
		return bls12381.G1Affine{}, fmt.Errorf("insufficient CV V2 aggregate-share outputs")
	}
	var aggregateErr error
	if validateOutputs {
		_, aggregateErr = cvAggregateScalarCanonicalBytes(aggregate, context, params)
	} else {
		_, aggregateErr = cvAggregateScalarCanonicalBytesAfterValidation(aggregate, context, params)
	}
	if aggregateErr != nil {
		return bls12381.G1Affine{}, aggregateErr
	}
	ordered := append([]*cvScalarShareOutputScalar(nil), outputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ReceiverIndex < ordered[j].ReceiverIndex })
	indices := make([]int, len(ordered))
	shares := make([]bls12381.G1Affine, len(ordered))
	blindShares := make([]bls12381.G1Affine, len(ordered))
	for i, output := range ordered {
		if output == nil || output.ReceiverIndex <= 0 || output.ReceiverIndex > len(receivers.encryptionPublicKeys) ||
			(i > 0 && output.ReceiverIndex == ordered[i-1].ReceiverIndex) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 aggregate-share output set")
		}
		if validateOutputs {
			if err := cvVerifyAggregateShareModeScalar(
				output, aggregate, context, params, &receivers.encryptionPublicKeys[output.ReceiverIndex-1], true, false,
			); err != nil {
				return bls12381.G1Affine{}, err
			}
		}
		indices[i], shares[i], blindShares[i] = output.ReceiverIndex, output.Y, output.YBlind
	}
	publicKey, err := cvInterpolateG1AtZero(indices, shares)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	blindConstant, err := cvInterpolateG1AtZero(indices, blindShares)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	var commitment bls12381.G1Affine
	commitment.Add(&publicKey, &blindConstant)
	if len(aggregate.CoefficientCommitments) == 0 || !commitment.Equal(&aggregate.CoefficientCommitments[0]) {
		return bls12381.G1Affine{}, fmt.Errorf("CV V2 aggregate-share interpolation mismatch")
	}
	if publicKey.IsInfinity() {
		return bls12381.G1Affine{}, fmt.Errorf("CV V2 threshold public key is identity")
	}
	return publicKey, nil
}
