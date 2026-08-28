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
	cvAggregateShareWireDomainV2      = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-share"
	cvAggregateShareChallengeDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-share/challenge"
)

type cvAggregateShareProofV2 struct {
	KeyCommitment             bls12381.G1Affine
	ScalarCipherCommitment    bls12381.G1Affine
	ScalarKnowledgeCommitment bls12381.G1Affine
	BlindingDecryptCommitment bls12381.G1Affine
	KeyResponse               fr.Element
	ScalarResponse            fr.Element
}

type cvScalarShareOutputV2 struct {
	AggregateDigest []byte
	ReceiverID      int
	ReceiverIndex   int
	Y               bls12381.G1Affine
	YBlind          bls12381.G1Affine
	Proof           cvAggregateShareProofV2
}

type cvAggregateShareDecryptionTimingsV2 struct {
	ScalarBoundedDLog       time.Duration
	BlindingGroupDecryption time.Duration
}

func cvDecryptAggregateShareV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, *cvScalarShareOutputV2, error) {
	scalar, output, _, err := cvDecryptAggregateShareMeasuredV2(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, receiverSecret,
	)
	return scalar, output, err
}

func cvDecryptAggregateShareMeasuredV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, *cvScalarShareOutputV2, cvAggregateShareDecryptionTimingsV2, error) {
	var timings cvAggregateShareDecryptionTimingsV2
	if err := cvValidateAggregateShareInputsV2(aggregate, context, params, receiverID, receiverIndex, receiverPublicKey); err != nil {
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
	solver := cvNewBoundedDLogSolverForBaseV2(&genG1, digitBound)
	timings.ScalarBoundedDLog += time.Since(started)
	for chunk := 0; chunk < chunks; chunk++ {
		plaintext := cvDecryptGroupCiphertextV2(&receiver.ScalarChunks[chunk], receiverSecret)
		started = time.Now()
		digit, ok := solver.solve(&plaintext)
		timings.ScalarBoundedDLog += time.Since(started)
		if !ok {
			return fr.Element{}, nil, timings, fmt.Errorf("CV V2 aggregate scalar chunk %d is outside [0,K(B-1)]", chunk)
		}
		digits[chunk] = digit
	}
	scalar, err := cvAggregateDigitsToScalarV2(digits, context.Profile.chunkBits, base, digitBound)
	if err != nil {
		return fr.Element{}, nil, timings, err
	}
	started = time.Now()
	yBlind := cvDecryptGroupCiphertextV2(&receiver.Blinding, receiverSecret)
	timings.BlindingGroupDecryption += time.Since(started)
	output := &cvScalarShareOutputV2{
		AggregateDigest: append([]byte(nil), aggregate.Digest...), ReceiverID: receiverID, ReceiverIndex: receiverIndex,
		Y: cvPointTimes(&genG1, &scalar), YBlind: yBlind,
	}
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return fr.Element{}, nil, timings, fmt.Errorf("CV V2 aggregate decrypted shares do not open receiver evaluation")
	}
	proof, err := cvProveAggregateShareV2(aggregate, context, receiverPublicKey, receiverSecret, scalar, output)
	if err != nil {
		return fr.Element{}, nil, timings, err
	}
	output.Proof = *proof
	if err := cvVerifyAggregateShareAfterValidationV2(
		output, aggregate, context, params, receiverPublicKey,
	); err != nil {
		return fr.Element{}, nil, timings, err
	}
	return scalar, output, timings, nil
}

func cvProveAggregateShareV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverPublicKey *bls12381.G1Affine,
	receiverSecret, scalar fr.Element, output *cvScalarShareOutputV2,
) (*cvAggregateShareProofV2, error) {
	weighted, err := cvWeightedAggregateScalarV2(aggregate, context, output.ReceiverIndex)
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
	proof := &cvAggregateShareProofV2{
		KeyCommitment: cvPointTimes(&genG1, &keyNonce),
		ScalarCipherCommitment: cvPointSum(
			pointPtr(cvPointTimes(&weighted.r, &keyNonce)), pointPtr(cvPointTimes(&genG1, &scalarNonce)),
		),
		ScalarKnowledgeCommitment: cvPointTimes(&genG1, &scalarNonce),
		BlindingDecryptCommitment: cvPointTimes(&receiver.Blinding.r, &keyNonce),
	}
	challenge, err := cvAggregateShareChallengeV2(aggregate, context, receiverPublicKey, output, proof)
	if err != nil {
		return nil, err
	}
	proof.KeyResponse.Mul(&challenge, &receiverSecret).Add(&proof.KeyResponse, &keyNonce)
	proof.ScalarResponse.Mul(&challenge, &scalar).Add(&proof.ScalarResponse, &scalarNonce)
	return proof, nil
}

func cvVerifyAggregateShareV2(
	output *cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeV2(output, aggregate, context, params, receiverPublicKey, true, true)
}

func cvVerifyAggregateShareAfterPointDecodingV2(
	output *cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeV2(output, aggregate, context, params, receiverPublicKey, false, false)
}

func cvVerifyAggregateShareAfterValidationV2(
	output *cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyAggregateShareModeV2(output, aggregate, context, params, receiverPublicKey, false, false)
}

func cvVerifyAggregateShareModeV2(
	output *cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receiverPublicKey *bls12381.G1Affine, validatePoints, validateAggregate bool,
) error {
	var aggregateErr error
	if validateAggregate {
		aggregateErr = cvValidateAggregateShareInputsV2(
			aggregate, context, params, outputReceiverIDV2(output), outputReceiverIndexV2(output), receiverPublicKey,
		)
	} else {
		aggregateErr = cvValidateAggregateShareInputsAfterValidationV2(
			aggregate, context, params, outputReceiverIDV2(output), outputReceiverIndexV2(output), receiverPublicKey,
		)
	}
	if output == nil || aggregate == nil || output.ReceiverID < 0 || output.ReceiverIndex <= 0 || len(output.AggregateDigest) != 32 ||
		!bytes.Equal(output.AggregateDigest, aggregate.Digest) ||
		aggregateErr != nil || (validatePoints && (!cvValidG1(&output.Y, true) ||
		!cvValidG1(&output.YBlind, true) || !cvValidAggregateShareProofV2(&output.Proof))) {
		return fmt.Errorf("invalid CV V2 aggregate-share output")
	}
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return fmt.Errorf("CV V2 aggregate-share opening mismatch")
	}
	weighted, err := cvWeightedAggregateScalarV2(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return err
	}
	challenge, err := cvAggregateShareChallengeV2(aggregate, context, receiverPublicKey, output, &output.Proof)
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

func outputReceiverIDV2(output *cvScalarShareOutputV2) int {
	if output == nil {
		return -1
	}
	return output.ReceiverID
}

func outputReceiverIndexV2(output *cvScalarShareOutputV2) int {
	if output == nil {
		return -1
	}
	return output.ReceiverIndex
}

func cvAggregateShareChallengeV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverPublicKey *bls12381.G1Affine,
	output *cvScalarShareOutputV2, proof *cvAggregateShareProofV2,
) (fr.Element, error) {
	if aggregate == nil || context == nil || output == nil || proof == nil ||
		output.ReceiverIndex <= 0 || output.ReceiverIndex > len(aggregate.Receivers) ||
		!cvValidG1(receiverPublicKey, false) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 aggregate-share challenge")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return fr.Element{}, err
	}
	weighted, err := cvWeightedAggregateScalarV2(aggregate, context, output.ReceiverIndex)
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
	return cvHashToFr(cvAggregateShareChallengeDomainV2, wire.Bytes())
}

func cvWeightedAggregateScalarV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverIndex int,
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

func cvAggregateDigitsToScalarV2(digits []uint64, chunkBits uint, base, bound uint64) (fr.Element, error) {
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

func cvValidateAggregateShareInputsV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvValidateAggregateShareInputsModeV2(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, true,
	)
}

func cvValidateAggregateShareInputsAfterValidationV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	return cvValidateAggregateShareInputsModeV2(
		aggregate, context, params, receiverID, receiverIndex, receiverPublicKey, false,
	)
}

func cvValidateAggregateShareInputsModeV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, validateAggregate bool,
) error {
	if context == nil || params.componentCount <= 0 || context.Profile.maxComponents != params.componentCount ||
		context.SharingDegree != params.newShareDegree || params.newShareThreshold != context.SharingDegree+1 ||
		cvValidateReceiverBindingV2(context, receiverID, receiverIndex, receiverPublicKey) != nil {
		return fmt.Errorf("invalid CV V2 aggregate-share parameters")
	}
	var err error
	if validateAggregate {
		_, err = cvAggregateV2CanonicalBytes(aggregate, context, params)
	} else {
		_, err = cvAggregateV2CanonicalBytesAfterValidation(aggregate, context, params)
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

func cvValidAggregateShareProofV2(proof *cvAggregateShareProofV2) bool {
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

func cvScalarShareOutputV2CanonicalBytes(output *cvScalarShareOutputV2) ([]byte, error) {
	return cvScalarShareOutputV2CanonicalBytesMode(output, true)
}

func cvScalarShareOutputV2CanonicalBytesAfterValidation(output *cvScalarShareOutputV2) ([]byte, error) {
	return cvScalarShareOutputV2CanonicalBytesMode(output, false)
}

func cvScalarShareOutputV2CanonicalBytesMode(output *cvScalarShareOutputV2, validatePoints bool) ([]byte, error) {
	if output == nil || len(output.AggregateDigest) != 32 || output.ReceiverID < 0 || output.ReceiverIndex <= 0 ||
		(validatePoints && (!cvValidG1(&output.Y, true) || !cvValidG1(&output.YBlind, true) ||
			!cvValidAggregateShareProofV2(&output.Proof))) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateShareWireDomainV2))
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

func cvDecodeScalarShareOutputV2(
	wire []byte, aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receivers *cvReceiverKeyMaterialV2,
) (*cvScalarShareOutputV2, error) {
	if cvValidateReceiverMaterialForLeafV2(context, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver registry")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateShareWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainV2)) {
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
	output := &cvScalarShareOutputV2{
		AggregateDigest: digest, ReceiverID: int(receiverID), ReceiverIndex: int(receiverIndex),
		Y: points[0], YBlind: points[1], Proof: cvAggregateShareProofV2{
			KeyCommitment: points[2], ScalarCipherCommitment: points[3],
			ScalarKnowledgeCommitment: points[4], BlindingDecryptCommitment: points[5],
			KeyResponse: keyResponse, ScalarResponse: scalarResponse,
		},
	}
	canonical, err := cvScalarShareOutputV2CanonicalBytesAfterValidation(output)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate-share output")
	}
	index := output.ReceiverIndex - 1
	if index < 0 || index >= len(receivers.encryptionPublicKeys) {
		return nil, fmt.Errorf("CV V2 aggregate-share receiver is outside registry")
	}
	if err := cvVerifyAggregateShareAfterPointDecodingV2(
		output, aggregate, context, params, &receivers.encryptionPublicKeys[index],
	); err != nil {
		return nil, err
	}
	return output, nil
}

func cvRecoverThresholdPublicKeyV2(
	outputs []*cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receivers *cvReceiverKeyMaterialV2,
) (bls12381.G1Affine, error) {
	return cvRecoverThresholdPublicKeyModeV2(outputs, aggregate, context, params, receivers, true)
}

func cvRecoverThresholdPublicKeyAfterValidationV2(
	outputs []*cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receivers *cvReceiverKeyMaterialV2,
) (bls12381.G1Affine, error) {
	return cvRecoverThresholdPublicKeyModeV2(outputs, aggregate, context, params, receivers, false)
}

func cvRecoverThresholdPublicKeyModeV2(
	outputs []*cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receivers *cvReceiverKeyMaterialV2, validateOutputs bool,
) (bls12381.G1Affine, error) {
	if cvValidateReceiverMaterialForLeafV2(context, receivers) != nil || len(outputs) < params.newShareThreshold {
		return bls12381.G1Affine{}, fmt.Errorf("insufficient CV V2 aggregate-share outputs")
	}
	var aggregateErr error
	if validateOutputs {
		_, aggregateErr = cvAggregateV2CanonicalBytes(aggregate, context, params)
	} else {
		_, aggregateErr = cvAggregateV2CanonicalBytesAfterValidation(aggregate, context, params)
	}
	if aggregateErr != nil {
		return bls12381.G1Affine{}, aggregateErr
	}
	ordered := append([]*cvScalarShareOutputV2(nil), outputs...)
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
			if err := cvVerifyAggregateShareModeV2(
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
