package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvAggregateHeaderScalarDomain  = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-header"
	cvSelectionDigestScalarDomain  = "ARL-CV-sAPVSS/v2-scalar-group/selection-digest"
	cvAggregateWireScalarDomain    = "ARL-CV-sAPVSS/v2-scalar-group/aggregate"
	cvAggregateDigestScalarDomain  = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-digest"
	cvAggregatePayloadScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/aggregate-payload-digest"
)

type cvAggregateComponentScalar struct {
	DealerID   int
	LeafDigest []byte
}

type cvAggregateReceiverScalar struct {
	ReceiverID    int
	ReceiverIndex int
	Evaluation    bls12381.G1Affine
	ScalarChunks  []cvElGamalCiphertext
	Blinding      cvElGamalCiphertext
}

// cvAggregateScalar contains only the manifest and homomorphic aggregate.
// Component proofs and ACKs remain in component APDB payloads and are checked
// by cvAVerScalar before this object is accepted.
type cvAggregateScalar struct {
	ContextDigest          []byte
	Components             []cvAggregateComponentScalar
	CoefficientCommitments []bls12381.G1Affine
	Receivers              []cvAggregateReceiverScalar
	Digest                 []byte
}

// cvAggregateHeaderScalar is intentionally independent from legacy AggHeader.
// All fields are public and sufficient for VCert, ARC and handoff binding.
type cvAggregateHeaderScalar struct {
	ContextDigest   []byte
	ProposerID      int
	PoolDigest      []byte
	SelectionDigest []byte
	AggregateDigest []byte
	PayloadDigest   []byte
	APDBInstance    []byte
	APDBRoot        []byte
}

func cvAggScalar(
	leaves []*cvLeafScalar, context *cvLeafContextScalar, params cvScalarParams,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvAggregateScalar, error) {
	if context == nil || params.componentCount <= 0 || len(leaves) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 aggregate input")
	}
	for leafIndex, leaf := range leaves {
		if err := cvVerifyAPVSSScalar(leaf, context, receivers, validators); err != nil {
			return nil, fmt.Errorf("verify CV V2 aggregate component %d: %w", leafIndex, err)
		}
	}
	return cvAggVerifiedScalar(leaves, context, params)
}

// cvAggVerifiedScalar is restricted to leaves already accepted by cvVerifyAPVSSScalar.
func cvAggVerifiedScalar(
	leaves []*cvLeafScalar, context *cvLeafContextScalar, params cvScalarParams,
) (*cvAggregateScalar, error) {
	if context == nil || params.componentCount <= 0 || len(leaves) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 aggregate input")
	}
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		return nil, err
	}
	aggregate := &cvAggregateScalar{
		ContextDigest:          append([]byte(nil), contextDigest...),
		Components:             make([]cvAggregateComponentScalar, len(leaves)),
		CoefficientCommitments: make([]bls12381.G1Affine, context.SharingDegree+1),
		Receivers:              make([]cvAggregateReceiverScalar, len(context.NewRoster)),
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	for i, receiverID := range context.NewRoster {
		aggregate.Receivers[i] = cvAggregateReceiverScalar{
			ReceiverID: receiverID, ReceiverIndex: i + 1,
			ScalarChunks: make([]cvElGamalCiphertext, chunks),
		}
	}
	dealers := make(map[int]struct{}, len(leaves))
	for leafIndex, leaf := range leaves {
		if leaf == nil || len(leaf.Digest) != 32 || len(leaf.CoefficientCommitments) != context.SharingDegree+1 ||
			len(leaf.Receivers) != len(context.NewRoster) {
			return nil, fmt.Errorf("invalid verified CV V2 aggregate component %d", leafIndex)
		}
		if _, duplicate := dealers[leaf.DealerID]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 aggregate dealer")
		}
		dealers[leaf.DealerID] = struct{}{}
		aggregate.Components[leafIndex] = cvAggregateComponentScalar{
			DealerID: leaf.DealerID, LeafDigest: append([]byte(nil), leaf.Digest...),
		}
		for coefficient := range aggregate.CoefficientCommitments {
			aggregate.CoefficientCommitments[coefficient].Add(
				&aggregate.CoefficientCommitments[coefficient], &leaf.CoefficientCommitments[coefficient],
			)
		}
		for receiverIndex := range aggregate.Receivers {
			target := &aggregate.Receivers[receiverIndex]
			source := &leaf.Receivers[receiverIndex].Offer
			target.Evaluation.Add(&target.Evaluation, &source.Evaluation)
			for chunk := 0; chunk < chunks; chunk++ {
				target.ScalarChunks[chunk].r.Add(
					&target.ScalarChunks[chunk].r, &source.ScalarChunks[chunk].r,
				)
				target.ScalarChunks[chunk].c.Add(
					&target.ScalarChunks[chunk].c, &source.ScalarChunks[chunk].c,
				)
			}
			target.Blinding.r.Add(&target.Blinding.r, &source.Blinding.r)
			target.Blinding.c.Add(&target.Blinding.c, &source.Blinding.c)
		}
	}
	unsigned, err := cvAggregateScalarUnsignedCanonicalBytesAfterValidation(aggregate, context, params)
	if err != nil {
		return nil, err
	}
	aggregate.Digest = hashBytes([]byte(cvAggregateDigestScalarDomain), unsigned)
	if _, err := cvAggregateScalarCanonicalBytesAfterValidation(aggregate, context, params); err != nil {
		return nil, err
	}
	return aggregate, nil
}

func cvAggregateScalarUnsignedCanonicalBytes(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
) ([]byte, error) {
	return cvAggregateScalarUnsignedCanonicalBytesMode(aggregate, context, params, true, true)
}

func cvAggregateScalarUnsignedCanonicalBytesAfterValidation(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
) ([]byte, error) {
	return cvAggregateScalarUnsignedCanonicalBytesMode(aggregate, context, params, false, false)
}

func cvAggregateScalarUnsignedCanonicalBytesMode(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	validatePoints, validateEvaluations bool,
) ([]byte, error) {
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil || aggregate == nil || params.componentCount <= 0 ||
		!bytes.Equal(aggregate.ContextDigest, contextDigest) || len(aggregate.Components) != params.componentCount ||
		len(aggregate.CoefficientCommitments) != context.SharingDegree+1 ||
		len(aggregate.Receivers) != len(context.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 aggregate")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateWireScalarDomain))
	_ = cvWriteBytes(&wire, aggregate.ContextDigest)
	if err := cvWriteUint32(&wire, len(aggregate.Components)); err != nil {
		return nil, err
	}
	dealers := make(map[int]struct{}, len(aggregate.Components))
	for _, component := range aggregate.Components {
		if component.DealerID < 0 || len(component.LeafDigest) != 32 ||
			!cvMemberInRosterScalar(component.DealerID, context.OldRoster) {
			return nil, fmt.Errorf("invalid CV V2 aggregate component")
		}
		if _, duplicate := dealers[component.DealerID]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 aggregate dealer")
		}
		dealers[component.DealerID] = struct{}{}
		cvWriteUint64(&wire, uint64(component.DealerID))
		_ = cvWriteBytes(&wire, component.LeafDigest)
	}
	if err := cvWritePointVectorMode(&wire, aggregate.CoefficientCommitments, validatePoints); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(aggregate.Receivers)); err != nil {
		return nil, err
	}
	for i := range aggregate.Receivers {
		receiver := &aggregate.Receivers[i]
		if receiver.ReceiverID != context.NewRoster[i] || receiver.ReceiverIndex != i+1 ||
			(validatePoints && !cvValidG1(&receiver.Evaluation, true)) {
			return nil, fmt.Errorf("invalid CV V2 aggregate receiver")
		}
		if validateEvaluations {
			expectedEvaluation := cvEvaluateCommitments(aggregate.CoefficientCommitments, i+1)
			if !receiver.Evaluation.Equal(&expectedEvaluation) {
				return nil, fmt.Errorf("CV V2 aggregate evaluation mismatch")
			}
		}
		cvWriteUint64(&wire, uint64(receiver.ReceiverID))
		cvWriteUint64(&wire, uint64(receiver.ReceiverIndex))
		cvWritePoint(&wire, &receiver.Evaluation)
		if len(receiver.ScalarChunks) != chunks || (validatePoints && !cvValidCiphertext(&receiver.Blinding)) {
			return nil, fmt.Errorf("invalid CV V2 aggregate ciphertext shape")
		}
		if err := cvWriteUint32(&wire, chunks); err != nil {
			return nil, err
		}
		for chunk := range receiver.ScalarChunks {
			ciphertext := &receiver.ScalarChunks[chunk]
			if validatePoints && !cvValidCiphertext(ciphertext) {
				return nil, fmt.Errorf("invalid CV V2 aggregate scalar ciphertext")
			}
			cvWriteCiphertext(&wire, ciphertext)
		}
		cvWriteCiphertext(&wire, &receiver.Blinding)
	}
	return wire.Bytes(), nil
}

func cvAggregateScalarCanonicalBytes(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
) ([]byte, error) {
	return cvAggregateScalarCanonicalBytesMode(aggregate, context, params, true, true)
}

func cvAggregateScalarCanonicalBytesAfterPointDecoding(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
) ([]byte, error) {
	return cvAggregateScalarCanonicalBytesMode(aggregate, context, params, false, true)
}

func cvAggregateScalarCanonicalBytesAfterValidation(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
) ([]byte, error) {
	return cvAggregateScalarCanonicalBytesMode(aggregate, context, params, false, false)
}

func cvAggregateScalarCanonicalBytesMode(
	aggregate *cvAggregateScalar, context *cvLeafContextScalar, params cvScalarParams,
	validatePoints, validateEvaluations bool,
) ([]byte, error) {
	if aggregate == nil || len(aggregate.Digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate wire")
	}
	unsigned, err := cvAggregateScalarUnsignedCanonicalBytesMode(
		aggregate, context, params, validatePoints, validateEvaluations,
	)
	if err != nil {
		return nil, err
	}
	wantDigest := hashBytes([]byte(cvAggregateDigestScalarDomain), unsigned)
	if !bytes.Equal(aggregate.Digest, wantDigest) {
		return nil, fmt.Errorf("CV V2 aggregate digest mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, aggregate.Digest)
	return wire.Bytes(), nil
}

func cvDecodeAggregateScalar(wire []byte, context *cvLeafContextScalar, params cvScalarParams) (*cvAggregateScalar, error) {
	if len(wire) == 0 || len(wire) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid CV V2 aggregate wire length")
	}
	r := newCVWireReader(wire)
	unsignedWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate framing")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate digest framing")
	}
	unsigned := newCVWireReader(unsignedWire)
	domain, err := unsigned.bytes(len(cvAggregateWireScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateWireScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate domain")
	}
	contextDigest, err := unsigned.bytes(32)
	wantContext, contextErr := cvLeafContextDigestScalar(context)
	if err != nil || contextErr != nil || !bytes.Equal(contextDigest, wantContext) {
		return nil, fmt.Errorf("CV V2 aggregate context mismatch")
	}
	componentCount, err := unsigned.uint32()
	if err != nil || componentCount != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 aggregate component count")
	}
	aggregate := &cvAggregateScalar{ContextDigest: contextDigest, Components: make([]cvAggregateComponentScalar, componentCount), Digest: digest}
	for i := range aggregate.Components {
		dealer, readErr := unsigned.uint64()
		if readErr != nil || dealer > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid CV V2 aggregate dealer")
		}
		leafDigest, readErr := unsigned.bytes(32)
		if readErr != nil || len(leafDigest) != 32 {
			return nil, fmt.Errorf("invalid CV V2 aggregate leaf digest")
		}
		aggregate.Components[i] = cvAggregateComponentScalar{DealerID: int(dealer), LeafDigest: leafDigest}
	}
	aggregate.CoefficientCommitments, err = cvReadExactPointVector(unsigned, context.SharingDegree+1, "V2 aggregate coefficients")
	if err != nil {
		return nil, err
	}
	receiverCount, err := unsigned.uint32()
	if err != nil || receiverCount != len(context.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 aggregate receiver count")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	aggregate.Receivers = make([]cvAggregateReceiverScalar, receiverCount)
	for i := range aggregate.Receivers {
		receiverID, readErr := unsigned.uint64()
		if readErr != nil || receiverID > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid CV V2 aggregate receiver ID")
		}
		receiverIndex, readErr := unsigned.uint64()
		if readErr != nil || receiverIndex > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid CV V2 aggregate receiver index")
		}
		evaluation, readErr := unsigned.point()
		if readErr != nil {
			return nil, fmt.Errorf("invalid CV V2 aggregate evaluation")
		}
		receiver := &aggregate.Receivers[i]
		receiver.ReceiverID, receiver.ReceiverIndex, receiver.Evaluation = int(receiverID), int(receiverIndex), evaluation
		if err := cvReadExactCount(unsigned, chunks, "V2 aggregate scalar chunks"); err != nil {
			return nil, err
		}
		if err := cvRequireRemaining(unsigned, chunks+1, 2*bls12381.SizeOfG1AffineCompressed, "V2 aggregate ciphertexts"); err != nil {
			return nil, err
		}
		receiver.ScalarChunks = make([]cvElGamalCiphertext, chunks)
		for chunk := 0; chunk < chunks; chunk++ {
			rPoint, pointErr := unsigned.point()
			if pointErr != nil {
				return nil, fmt.Errorf("invalid CV V2 aggregate scalar ciphertext R")
			}
			cPoint, pointErr := unsigned.point()
			if pointErr != nil {
				return nil, fmt.Errorf("invalid CV V2 aggregate scalar ciphertext W")
			}
			receiver.ScalarChunks[chunk] = cvElGamalCiphertext{r: rPoint, c: cPoint}
		}
		receiver.Blinding, err = unsigned.ciphertext()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 aggregate blinding ciphertext")
		}
	}
	if unsigned.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 aggregate bytes")
	}
	canonical, err := cvAggregateScalarCanonicalBytesAfterPointDecoding(aggregate, context, params)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate")
	}
	return aggregate, nil
}

func cvAggregatePayloadDigestScalar(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid CV V2 aggregate payload")
	}
	return hashBytes([]byte(cvAggregatePayloadScalarDomain), payload), nil
}

// cvAVerScalar validates every selected component through the unique APVSS
// verifier, recomputes the aggregate, and compares canonical payload bytes.
func cvAVerScalar(
	payload []byte, leaves []*cvLeafScalar, context *cvLeafContextScalar, params cvScalarParams,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvAggregateScalar, error) {
	decoded, err := cvDecodeAggregateScalar(payload, context, params)
	if err != nil {
		return nil, err
	}
	recomputed, err := cvAggScalar(leaves, context, params, receivers, validators)
	if err != nil {
		return nil, err
	}
	want, err := cvAggregateScalarCanonicalBytesAfterValidation(recomputed, context, params)
	if err != nil || !bytes.Equal(payload, want) {
		return nil, fmt.Errorf("CV V2 aggregate payload does not match selected components")
	}
	return decoded, nil
}

func cvAVerVerifiedScalar(
	payload []byte, leaves []*cvLeafScalar, context *cvLeafContextScalar, params cvScalarParams,
) (*cvAggregateScalar, error) {
	decoded, err := cvDecodeAggregateScalar(payload, context, params)
	if err != nil {
		return nil, err
	}
	recomputed, err := cvAggVerifiedScalar(leaves, context, params)
	if err != nil {
		return nil, err
	}
	want, err := cvAggregateScalarCanonicalBytesAfterValidation(recomputed, context, params)
	if err != nil || !bytes.Equal(payload, want) {
		return nil, fmt.Errorf("CV V2 aggregate payload does not match selected components")
	}
	return decoded, nil
}

func cvVerifyAggregateHeaderPayloadScalar(
	header *cvAggregateHeaderScalar, payload []byte, aggregate *cvAggregateScalar,
) error {
	if header == nil || aggregate == nil || len(aggregate.Digest) != 32 ||
		!bytes.Equal(header.ContextDigest, aggregate.ContextDigest) ||
		!bytes.Equal(header.AggregateDigest, aggregate.Digest) {
		return fmt.Errorf("CV V2 aggregate header does not bind aggregate")
	}
	payloadDigest, err := cvAggregatePayloadDigestScalar(payload)
	if err != nil || !bytes.Equal(header.PayloadDigest, payloadDigest) {
		return fmt.Errorf("CV V2 aggregate header does not bind payload")
	}
	return nil
}

func cvAggregateInstanceDigestScalar(contextDigest []byte, proposerID int, poolDigest, selectionDigest []byte) ([]byte, error) {
	if len(contextDigest) != 32 || proposerID < 0 || len(poolDigest) != 32 || len(selectionDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate instance input")
	}
	var proposer bytes.Buffer
	cvWriteUint64(&proposer, uint64(proposerID))
	return cvAPDBInstanceDigestScalar("AGG", contextDigest, proposer.Bytes(), poolDigest, selectionDigest)
}

func cvSelectionDigestScalar(coin *cvCoinOutputScalar, selectedIndices []int, poolSize, componentCount int) ([]byte, error) {
	if coin == nil || poolSize <= 0 || componentCount <= 0 || len(selectedIndices) != componentCount {
		return nil, fmt.Errorf("invalid CV V2 selection digest input")
	}
	want, err := cvSelectedPoolIndicesScalar(poolSize, componentCount, coin.Value)
	if err != nil || !equalInts(selectedIndices, want) {
		return nil, fmt.Errorf("invalid CV V2 contributor selection")
	}
	coinWire, err := cvCoinOutputScalarCanonicalBytes(coin)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, coinWire)
	if err := cvWriteUint32(&wire, len(selectedIndices)); err != nil {
		return nil, err
	}
	for _, index := range selectedIndices {
		cvWriteUint64(&wire, uint64(index))
	}
	return hashBytes([]byte(cvSelectionDigestScalarDomain), wire.Bytes()), nil
}

func cvAggregateHeaderScalarCanonicalBytes(header *cvAggregateHeaderScalar) ([]byte, error) {
	if header == nil || len(header.ContextDigest) != 32 || header.ProposerID < 0 || len(header.PoolDigest) != 32 ||
		len(header.SelectionDigest) != 32 || len(header.AggregateDigest) != 32 || len(header.PayloadDigest) != 32 ||
		len(header.APDBInstance) != 32 || len(header.APDBRoot) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate header")
	}
	wantInstance, err := cvAggregateInstanceDigestScalar(header.ContextDigest, header.ProposerID, header.PoolDigest, header.SelectionDigest)
	if err != nil || !bytes.Equal(wantInstance, header.APDBInstance) {
		return nil, fmt.Errorf("CV V2 aggregate header instance mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateHeaderScalarDomain))
	_ = cvWriteBytes(&wire, header.ContextDigest)
	cvWriteUint64(&wire, uint64(header.ProposerID))
	for _, field := range [][]byte{header.PoolDigest, header.SelectionDigest, header.AggregateDigest, header.PayloadDigest, header.APDBInstance, header.APDBRoot} {
		_ = cvWriteBytes(&wire, field)
	}
	return wire.Bytes(), nil
}

func cvDecodeAggregateHeaderScalar(wire []byte) (*cvAggregateHeaderScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateHeaderScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateHeaderScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate header domain")
	}
	context, err := r.bytes(32)
	if err != nil || len(context) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate header context")
	}
	proposer, err := r.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 aggregate header proposer")
	}
	fields := make([][]byte, 6)
	for i := range fields {
		fields[i], err = r.bytes(32)
		if err != nil || len(fields[i]) != 32 {
			return nil, fmt.Errorf("invalid CV V2 aggregate header field")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate header suffix")
	}
	header := &cvAggregateHeaderScalar{ContextDigest: context, ProposerID: int(proposer), PoolDigest: fields[0], SelectionDigest: fields[1], AggregateDigest: fields[2], PayloadDigest: fields[3], APDBInstance: fields[4], APDBRoot: fields[5]}
	canonical, err := cvAggregateHeaderScalarCanonicalBytes(header)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate header")
	}
	return header, nil
}
