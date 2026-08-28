package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvAggregateDomain = "ARL-CV-sAPVSS/aggregate"
	cvReceiptDomain   = "ARL-CV-sAPVSS/receipt"
	cvDLEQDomain      = "ARL-CV-sAPVSS/receipt-dleq"
)

type cvAggregateReceiver struct {
	receiverIndex     int
	receiverPublicKey bls12381.G1Affine
	scalarChunks      []cvElGamalCiphertext
	blinding          cvElGamalCiphertext
}

type cvAggregateTranscript struct {
	context                cvLeafContext
	dealerIDs              []uint64
	leafDigests            [][]byte
	coefficientCommitments []bls12381.G1Affine
	receivers              []cvAggregateReceiver
	digestWire             []byte
	digest                 []byte
}

// cvVerifiedLeaf carries the canonical bytes that were accepted by a full
// leaf verification. Callers must recheck those bytes before using the leaf so
// a mutable in-memory object cannot inherit stale verified status.
type cvVerifiedLeaf struct {
	leaf          *cvLeaf
	apvss         *apvssLeafPrototype
	contextDigest []byte
	leafDigest    []byte
	canonicalWire []byte
	serviceSealed bool
}

// cvAcceptedDecodedAPVSSLeaf wraps a prototype returned by
// apvssDecodeLeafPrototype. That decoder has already verified both the
// structural leaf and its ACK/fallback partition.
func cvAcceptedDecodedAPVSSLeaf(
	context *cvLeafContext,
	prototype *apvssLeafPrototype,
	canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if prototype == nil || prototype.leaf == nil ||
		!bytes.Equal(cvLeafContextDigest(context), cvLeafContextDigest(&prototype.leaf.context)) {
		return nil, fmt.Errorf("accepted APVSS leaf context mismatch")
	}
	wire := canonicalWire
	if len(wire) == 0 {
		var err error
		wire, err = apvssLeafPrototypeCanonicalBytes(prototype)
		if err != nil {
			return nil, err
		}
	}
	digest := hashBytes([]byte(apvssLeafDigestDomain), wire)
	if len(prototype.digest) > 0 && !bytes.Equal(prototype.digest, digest) {
		return nil, fmt.Errorf("accepted APVSS leaf digest mismatch")
	}
	prototype.digest = append([]byte(nil), digest...)
	return &cvVerifiedLeaf{
		leaf: prototype.leaf, apvss: prototype,
		contextDigest: append([]byte(nil), cvLeafContextDigest(context)...),
		leafDigest:    append([]byte(nil), digest...),
		canonicalWire: append([]byte(nil), wire...),
	}, nil
}

type cvMultiDLEQProof struct {
	tKey, tScalar, tBlinding bls12381.G1Affine
	z                        fr.Element
	feldman                  bool
}

type cvReceipt struct {
	aggregateDigest []byte
	receiverIndex   int
	publicScalar    bls12381.G1Affine
	blindingOpening bls12381.G1Affine
	proof           cvMultiDLEQProof
	digestWire      []byte
	digest          []byte
}

func cvAgg(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggCalls.Add(1)
	}
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(leaves) == 0 || len(leaves) > context.profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate component count")
	}
	for _, leaf := range leaves {
		if leaf == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS aggregate leaf")
		}
		if err := cvVerifyLeaf(context, leaf); err != nil {
			return nil, fmt.Errorf("dealer %d leaf: %w", leaf.dealerID, err)
		}
	}
	return cvAggregateAcceptedLeaves(context, leaves)
}

func cvAcceptedLeaf(context *cvLeafContext, leaf *cvLeaf, canonicalWire []byte) (*cvVerifiedLeaf, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if leaf == nil || len(leaf.digest) != 32 {
		return nil, fmt.Errorf("invalid accepted CV-sAPVSS leaf")
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	if len(canonicalWire) > 0 && !bytes.Equal(wire, canonicalWire) {
		return nil, fmt.Errorf("accepted CV-sAPVSS leaf wire mismatch")
	}
	contextDigest := cvLeafContextDigest(context)
	if !bytes.Equal(contextDigest, cvLeafContextDigest(&leaf.context)) ||
		!bytes.Equal(leaf.digest, hashBytes([]byte(cvLeafDigestDomain), wire)) {
		return nil, fmt.Errorf("accepted CV-sAPVSS leaf binding mismatch")
	}
	return &cvVerifiedLeaf{
		leaf: leaf, contextDigest: append([]byte(nil), contextDigest...),
		leafDigest: append([]byte(nil), leaf.digest...), canonicalWire: append([]byte(nil), wire...),
	}, nil
}

func cvValidateAcceptedLeaf(context *cvLeafContext, accepted *cvVerifiedLeaf) error {
	if accepted == nil || accepted.leaf == nil ||
		!bytes.Equal(accepted.contextDigest, cvLeafContextDigest(context)) {
		return fmt.Errorf("invalid verified CV-sAPVSS leaf token")
	}
	if accepted.apvss != nil {
		if accepted.apvss.leaf != accepted.leaf {
			return fmt.Errorf("invalid verified APVSS leaf token")
		}
		wire, err := apvssLeafPrototypeCanonicalBytes(accepted.apvss)
		if err != nil || !bytes.Equal(wire, accepted.canonicalWire) ||
			!bytes.Equal(accepted.leafDigest, accepted.apvss.digest) ||
			!bytes.Equal(accepted.leafDigest, hashBytes([]byte(apvssLeafDigestDomain), wire)) {
			return fmt.Errorf("mutated verified APVSS leaf")
		}
		return nil
	}
	if !bytes.Equal(accepted.leafDigest, accepted.leaf.digest) {
		return fmt.Errorf("invalid verified CV-sAPVSS leaf token")
	}
	wire, err := cvLeafCanonicalBytes(accepted.leaf)
	if err != nil || !bytes.Equal(wire, accepted.canonicalWire) ||
		!bytes.Equal(accepted.leafDigest, hashBytes([]byte(cvLeafDigestDomain), wire)) {
		return fmt.Errorf("mutated verified CV-sAPVSS leaf")
	}
	return nil
}

func cvAggVerified(context *cvLeafContext, accepted []*cvVerifiedLeaf) (*cvAggregateTranscript, error) {
	return cvAggVerifiedMode(context, accepted, false)
}

func cvAggServiceVerified(context *cvLeafContext, accepted []*cvVerifiedLeaf) (*cvAggregateTranscript, error) {
	return cvAggVerifiedMode(context, accepted, true)
}

func cvAggVerifiedMode(context *cvLeafContext, accepted []*cvVerifiedLeaf, requireServiceSeal bool) (*cvAggregateTranscript, error) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggVerifiedCalls.Add(1)
	}
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(accepted) == 0 || len(accepted) > context.profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS verified aggregate component count")
	}
	leaves := make([]*cvLeaf, len(accepted))
	contextDigest := cvLeafContextDigest(context)
	for i := range accepted {
		if requireServiceSeal {
			if accepted[i] == nil || !accepted[i].serviceSealed || accepted[i].leaf == nil ||
				len(accepted[i].leafDigest) != 32 || !bytes.Equal(accepted[i].contextDigest, contextDigest) {
				return nil, fmt.Errorf("invalid sealed CV-sAPVSS leaf token")
			}
			if accepted[i].apvss != nil {
				if accepted[i].apvss.leaf != accepted[i].leaf ||
					!bytes.Equal(accepted[i].leafDigest, accepted[i].apvss.digest) {
					return nil, fmt.Errorf("invalid sealed APVSS leaf token")
				}
			} else if !bytes.Equal(accepted[i].leafDigest, accepted[i].leaf.digest) {
				return nil, fmt.Errorf("invalid sealed CV-sAPVSS leaf token")
			}
		} else {
			if err := cvValidateAcceptedLeaf(context, accepted[i]); err != nil {
				return nil, err
			}
		}
		leaves[i] = accepted[i].leaf
	}
	agg, err := cvAggregateAcceptedLeavesUnfinalized(context, leaves)
	if err != nil {
		return nil, err
	}
	for i := range accepted {
		agg.leafDigests[i] = append([]byte(nil), accepted[i].leafDigest...)
	}
	return cvFinalizeAggregate(agg)
}

func cvAggregateAcceptedLeaves(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	agg, err := cvAggregateAcceptedLeavesUnfinalized(context, leaves)
	if err != nil {
		return nil, err
	}
	return cvFinalizeAggregate(agg)
}

func cvAggregateReceiverFast(
	profile cvChunkProfile,
	shares []*cvEncryptedShare,
) (cvAggregateReceiver, error) {
	_, _, chunks, err := cvProfile(profile)
	if err != nil || len(shares) == 0 || shares[0] == nil ||
		len(shares[0].scalarChunks) != chunks {
		return cvAggregateReceiver{}, fmt.Errorf("invalid CV-sAPVSS aggregate receiver input")
	}
	receiverKey := shares[0].receiverPublicKey
	jacobian := make([]bls12381.G1Jac, 2*chunks+2)
	for _, share := range shares {
		if share == nil || len(share.scalarChunks) != chunks ||
			!share.receiverPublicKey.Equal(&receiverKey) {
			return cvAggregateReceiver{}, fmt.Errorf("CV-sAPVSS aggregate mixes receiver lanes")
		}
		for chunk := range share.scalarChunks {
			jacobian[2*chunk].AddMixed(&share.scalarChunks[chunk].r)
			jacobian[2*chunk+1].AddMixed(&share.scalarChunks[chunk].c)
		}
		jacobian[2*chunks].AddMixed(&share.blinding.r)
		jacobian[2*chunks+1].AddMixed(&share.blinding.c)
	}
	affine := bls12381.BatchJacobianToAffineG1(jacobian)
	scalarChunks := make([]cvElGamalCiphertext, chunks)
	for chunk := range scalarChunks {
		scalarChunks[chunk] = cvElGamalCiphertext{
			r: affine[2*chunk], c: affine[2*chunk+1],
		}
	}
	return cvAggregateReceiver{
		receiverPublicKey: receiverKey,
		scalarChunks:      scalarChunks,
		blinding: cvElGamalCiphertext{
			r: affine[2*chunks], c: affine[2*chunks+1],
		},
	}, nil
}

func cvAggregateAcceptedLeavesUnfinalized(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	agg := &cvAggregateTranscript{
		context:     cvCloneLeafContext(*context),
		dealerIDs:   make([]uint64, len(leaves)),
		leafDigests: make([][]byte, len(leaves)),
		coefficientCommitments: make([]bls12381.G1Affine,
			context.sharingDegree+1),
		receivers: make([]cvAggregateReceiver, len(context.receiverPublicKeys)),
	}
	coefficientJacobian := make([]bls12381.G1Jac, len(agg.coefficientCommitments))
	for i, leaf := range leaves {
		if leaf == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS aggregate leaf")
		}
		if i > 0 && leaf.dealerID <= leaves[i-1].dealerID {
			return nil, fmt.Errorf("CV-sAPVSS aggregate dealer manifest is not ordered and distinct")
		}
		agg.dealerIDs[i] = leaf.dealerID
		agg.leafDigests[i] = append([]byte(nil), leaf.digest...)
		for j := range agg.coefficientCommitments {
			coefficientJacobian[j].AddMixed(&leaf.coefficientCommitments[j])
		}
	}
	agg.coefficientCommitments = bls12381.BatchJacobianToAffineG1(coefficientJacobian)
	err := cvRunParallelChecks(len(agg.receivers), func(receiverIndex int) error {
		shares := make([]*cvEncryptedShare, len(leaves))
		for dealerIndex := range leaves {
			shares[dealerIndex] = leaves[dealerIndex].receivers[receiverIndex].encryptedShare
		}
		receiver, aggregateErr := cvAggregateReceiverFast(context.profile, shares)
		if aggregateErr != nil {
			return fmt.Errorf("aggregate receiver %d: %w", receiverIndex+1, aggregateErr)
		}
		receiver.receiverIndex = receiverIndex + 1
		agg.receivers[receiverIndex] = receiver
		return nil
	})
	if err != nil {
		return nil, err
	}
	return agg, nil
}

func cvFinalizeAggregate(agg *cvAggregateTranscript) (*cvAggregateTranscript, error) {
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return nil, err
	}
	agg.digestWire = append([]byte(nil), wire...)
	agg.digest = hashBytes([]byte(cvAggregateDomain), wire)
	return agg, nil
}

func cvAVer(context *cvLeafContext, agg *cvAggregateTranscript, leaves []*cvLeaf) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.averCalls.Add(1)
	}
	expected, err := cvAgg(context, leaves)
	if err != nil {
		return err
	}
	return cvCompareAggregate(agg, expected)
}

func cvAVerVerified(context *cvLeafContext, agg *cvAggregateTranscript, leaves []*cvVerifiedLeaf) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.averVerifiedCalls.Add(1)
	}
	expected, err := cvAggVerified(context, leaves)
	if err != nil {
		return err
	}
	return cvCompareAggregate(agg, expected)
}

func cvCompareAggregate(agg, expected *cvAggregateTranscript) error {
	gotWire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return err
	}
	if !bytes.Equal(agg.digestWire, gotWire) || !bytes.Equal(gotWire, expected.digestWire) ||
		!bytes.Equal(agg.digest, hashBytes([]byte(cvAggregateDomain), gotWire)) {
		return fmt.Errorf("CV-sAPVSS Aggregate wire or digest mismatch")
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.averSuccesses.Add(1)
	}
	return nil
}

func cvCheckAggregateDigest(agg *cvAggregateTranscript) error {
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return err
	}
	if !bytes.Equal(agg.digestWire, wire) || !bytes.Equal(agg.digest, hashBytes([]byte(cvAggregateDomain), wire)) {
		return fmt.Errorf("CV-sAPVSS Aggregate wire or digest mismatch")
	}
	return nil
}

func cvValidateAggregate(agg *cvAggregateTranscript) error {
	if agg == nil {
		return fmt.Errorf("nil CV-sAPVSS Aggregate")
	}
	if err := cvValidateLeafContext(&agg.context); err != nil {
		return err
	}
	if len(agg.dealerIDs) == 0 || len(agg.dealerIDs) > agg.context.profile.maxComponents ||
		len(agg.leafDigests) != len(agg.dealerIDs) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate dealer manifest")
	}
	for i, dealer := range agg.dealerIDs {
		if i > 0 && dealer <= agg.dealerIDs[i-1] {
			return fmt.Errorf("CV-sAPVSS aggregate dealer manifest is not canonical")
		}
		if len(agg.leafDigests[i]) != 32 {
			return fmt.Errorf("invalid CV-sAPVSS component leaf digest %d", i)
		}
	}
	if len(agg.coefficientCommitments) != agg.context.sharingDegree+1 ||
		len(agg.receivers) != len(agg.context.receiverPublicKeys) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate statement size")
	}
	chunks, err := cvChunkCount(agg.context.profile)
	if err != nil {
		return err
	}
	for i := range agg.coefficientCommitments {
		if !cvValidG1(&agg.coefficientCommitments[i], true) {
			return fmt.Errorf("invalid aggregate coefficient commitment %d", i)
		}
	}
	for i, receiver := range agg.receivers {
		if receiver.receiverIndex != i+1 || !receiver.receiverPublicKey.Equal(&agg.context.receiverPublicKeys[i]) ||
			!cvValidG1(&receiver.receiverPublicKey, false) || len(receiver.scalarChunks) != chunks ||
			!cvValidCiphertext(&receiver.blinding) {
			return fmt.Errorf("invalid aggregate receiver %d", i+1)
		}
		if agg.context.proofProfile == cvLeafStructuralProofProfile &&
			!cvIdentityCiphertext(&receiver.blinding) {
			return fmt.Errorf("structural aggregate receiver %d carries a non-identity blinding ciphertext", i+1)
		}
		for j := range receiver.scalarChunks {
			if !cvValidCiphertext(&receiver.scalarChunks[j]) {
				return fmt.Errorf("invalid aggregate scalar chunk %d", j)
			}
		}
	}
	return nil
}

func cvAggregateCanonicalBytes(agg *cvAggregateTranscript) ([]byte, error) {
	if err := cvValidateAggregate(agg); err != nil {
		return nil, err
	}
	contextWire, err := cvLeafContextCanonicalBytes(&agg.context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvAggregateDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, contextWire); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, cvLeafContextDigest(&agg.context)); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(agg.dealerIDs)); err != nil {
		return nil, err
	}
	for i, dealer := range agg.dealerIDs {
		cvWriteUint64(&wire, dealer)
		if err := cvWriteBytes(&wire, agg.leafDigests[i]); err != nil {
			return nil, err
		}
	}
	if err := cvWritePointVector(&wire, agg.coefficientCommitments); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(agg.receivers)); err != nil {
		return nil, err
	}
	for i := range agg.receivers {
		receiver := &agg.receivers[i]
		if err := cvWriteUint32(&wire, receiver.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &receiver.receiverPublicKey)
		if err := cvWriteUint32(&wire, len(receiver.scalarChunks)); err != nil {
			return nil, err
		}
		for j := range receiver.scalarChunks {
			cvWriteCiphertext(&wire, &receiver.scalarChunks[j])
		}
		if agg.context.proofProfile != cvLeafStructuralProofProfile {
			cvWriteCiphertext(&wire, &receiver.blinding)
		}
	}
	return wire.Bytes(), nil
}

func cvAggregateScalarCiphertext(agg *cvAggregateTranscript, receiverIndex int) (cvElGamalCiphertext, error) {
	if err := cvValidateAggregate(agg); err != nil {
		return cvElGamalCiphertext{}, err
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return cvElGamalCiphertext{}, fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	base, _, chunks, _ := cvProfile(agg.context.profile)
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	receiver := &agg.receivers[receiverIndex-1]
	var result cvElGamalCiphertext
	result.r.ScalarMultiplication(&genG1, big.NewInt(0))
	result.c.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range receiver.scalarChunks {
		result.r.Add(&result.r, pointPtr(cvPointTimes(&receiver.scalarChunks[i].r, &powers[i])))
		result.c.Add(&result.c, pointPtr(cvPointTimes(&receiver.scalarChunks[i].c, &powers[i])))
	}
	return result, nil
}

func cvDLEQTargets(agg *cvAggregateTranscript, receiverIndex int, publicScalar, blindingOpening *bls12381.G1Affine) (bls12381.G1Affine, bls12381.G1Affine, bls12381.G1Affine, bls12381.G1Affine, error) {
	scalarCipher, err := cvAggregateScalarCiphertext(agg, receiverIndex)
	if err != nil {
		return bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}, err
	}
	receiver := &agg.receivers[receiverIndex-1]
	var scalarTarget, blindingTarget bls12381.G1Affine
	scalarTarget.Sub(&scalarCipher.c, publicScalar)
	if blindingOpening == nil {
		return scalarCipher.r, scalarTarget, bls12381.G1Affine{}, bls12381.G1Affine{}, nil
	}
	blindingTarget.Sub(&receiver.blinding.c, blindingOpening)
	return scalarCipher.r, scalarTarget, receiver.blinding.r, blindingTarget, nil
}

func cvDLEQChallengeWithTargets(
	agg *cvAggregateTranscript,
	receiverIndex int,
	publicScalar, blindingOpening *bls12381.G1Affine,
	proof *cvMultiDLEQProof,
	scalarBase, scalarTarget, blindingBase, blindingTarget *bls12381.G1Affine,
) (fr.Element, error) {
	var points bytes.Buffer
	pointsToHash := []*bls12381.G1Affine{
		&agg.receivers[receiverIndex-1].receiverPublicKey,
		scalarBase, scalarTarget, publicScalar, &proof.tKey, &proof.tScalar,
	}
	if !proof.feldman {
		pointsToHash = append(pointsToHash, blindingBase, blindingTarget, blindingOpening, &proof.tBlinding)
	}
	for _, point := range pointsToHash {
		cvWritePoint(&points, point)
	}
	var indexWire bytes.Buffer
	cvWriteUint64(&indexWire, uint64(receiverIndex))
	return cvHashToFr(cvDLEQDomain, agg.digest, indexWire.Bytes(), points.Bytes())
}

func cvProveDLEQ(agg *cvAggregateTranscript, receiverIndex int, receiverSecret fr.Element, publicScalar, blindingOpening *bls12381.G1Affine) (*cvMultiDLEQProof, error) {
	var nonce fr.Element
	if _, err := nonce.SetRandom(); err != nil {
		return nil, fmt.Errorf("sample CV-sAPVSS receipt nonce: %w", err)
	}
	proof := &cvMultiDLEQProof{
		tKey:    cvPointTimes(&genG1, &nonce),
		feldman: agg.context.proofProfile == cvLeafStructuralProofProfile,
	}
	scalarCipher, err := cvAggregateScalarCiphertext(agg, receiverIndex)
	if err != nil {
		return nil, err
	}
	proof.tScalar = cvPointTimes(&scalarCipher.r, &nonce)
	receiver := &agg.receivers[receiverIndex-1]
	if !proof.feldman {
		proof.tBlinding = cvPointTimes(&receiver.blinding.r, &nonce)
	}
	var scalarTarget, blindingTarget bls12381.G1Affine
	scalarTarget.Sub(&scalarCipher.c, publicScalar)
	if !proof.feldman {
		blindingTarget.Sub(&receiver.blinding.c, blindingOpening)
	}
	challenge, err := cvDLEQChallengeWithTargets(
		agg, receiverIndex, publicScalar, blindingOpening, proof,
		&scalarCipher.r, &scalarTarget, &receiver.blinding.r, &blindingTarget,
	)
	if err != nil {
		return nil, err
	}
	proof.z.Mul(&challenge, &receiverSecret).Add(&proof.z, &nonce)
	return proof, nil
}

func cvDecShare(agg *cvAggregateTranscript, receiverSecret fr.Element, receiverIndex int) (*cvDecryptedShare, *cvReceipt, error) {
	return cvDecShareMode(agg, receiverSecret, receiverIndex, true)
}

func cvDecShareVerifiedAggregate(agg *cvAggregateTranscript, receiverSecret fr.Element, receiverIndex int) (*cvDecryptedShare, *cvReceipt, error) {
	return cvDecShareMode(agg, receiverSecret, receiverIndex, false)
}

func cvDecShareMode(agg *cvAggregateTranscript, receiverSecret fr.Element, receiverIndex int, checkAggregateDigest bool) (*cvDecryptedShare, *cvReceipt, error) {
	if checkAggregateDigest {
		if err := cvValidateAggregate(agg); err != nil {
			return nil, nil, err
		}
		if err := cvCheckAggregateDigest(agg); err != nil {
			return nil, nil, err
		}
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	receiver := &agg.receivers[receiverIndex-1]
	key, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		return nil, nil, err
	}
	if !key.Equal(&receiver.receiverPublicKey) {
		return nil, nil, fmt.Errorf("CV-sAPVSS receiver secret does not match aggregate key")
	}
	share := &cvEncryptedShare{
		receiverPublicKey: receiver.receiverPublicKey,
		scalarChunks:      append([]cvElGamalCiphertext(nil), receiver.scalarChunks...),
		blinding:          receiver.blinding,
		commitment:        cvEvaluateCommitments(agg.coefficientCommitments, receiverIndex),
	}
	decrypted, err := cvDecryptShare(agg.context.profile, receiverSecret, share, len(agg.dealerIDs))
	if err != nil {
		return nil, nil, err
	}
	proof, err := cvProveDLEQ(agg, receiverIndex, receiverSecret, &decrypted.publicScalar, &decrypted.blindingOpening)
	if err != nil {
		return nil, nil, err
	}
	receipt := &cvReceipt{
		aggregateDigest: append([]byte(nil), agg.digest...),
		receiverIndex:   receiverIndex,
		publicScalar:    decrypted.publicScalar,
		proof:           *proof,
	}
	if !proof.feldman {
		receipt.blindingOpening = decrypted.blindingOpening
	}
	wire, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		return nil, nil, err
	}
	receipt.digestWire = wire
	receipt.digest = hashBytes([]byte(cvReceiptDomain), wire)
	return decrypted, receipt, nil
}

func cvReceiptCanonicalBytes(receipt *cvReceipt) ([]byte, error) {
	if receipt == nil || len(receipt.aggregateDigest) != 32 || receipt.receiverIndex <= 0 ||
		!cvValidG1(&receipt.publicScalar, true) ||
		!cvValidG1(&receipt.proof.tKey, true) || !cvValidG1(&receipt.proof.tScalar, true) ||
		(!receipt.proof.feldman && (!cvValidG1(&receipt.blindingOpening, true) || !cvValidG1(&receipt.proof.tBlinding, true))) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvReceiptDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, receipt.aggregateDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, receipt.receiverIndex); err != nil {
		return nil, err
	}
	mode := byte(0)
	if receipt.proof.feldman {
		mode = 1
	}
	if err := cvWriteUint32(&wire, int(mode)); err != nil {
		return nil, err
	}
	points := []*bls12381.G1Affine{&receipt.publicScalar, &receipt.proof.tKey, &receipt.proof.tScalar}
	if !receipt.proof.feldman {
		points = []*bls12381.G1Affine{&receipt.publicScalar, &receipt.blindingOpening, &receipt.proof.tKey, &receipt.proof.tScalar, &receipt.proof.tBlinding}
	}
	for _, point := range points {
		cvWritePoint(&wire, point)
	}
	cvWriteScalar(&wire, &receipt.proof.z)
	return wire.Bytes(), nil
}

func cvVerifyShare(context *cvLeafContext, agg *cvAggregateTranscript, receiverIndex int, receipt *cvReceipt) error {
	return cvVerifyShareMode(context, agg, receiverIndex, receipt, true)
}

func cvVerifyShareVerifiedAggregate(context *cvLeafContext, agg *cvAggregateTranscript, receiverIndex int, receipt *cvReceipt) error {
	return cvVerifyShareMode(context, agg, receiverIndex, receipt, false)
}

func cvVerifyShareMode(context *cvLeafContext, agg *cvAggregateTranscript, receiverIndex int, receipt *cvReceipt, checkAggregateDigest bool) error {
	if err := cvValidateLeafContext(context); err != nil {
		return err
	}
	if err := cvValidateAggregate(agg); err != nil {
		return err
	}
	if checkAggregateDigest {
		if err := cvCheckAggregateDigest(agg); err != nil {
			return err
		}
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	contextWire, err := cvLeafContextCanonicalBytes(context)
	if err != nil {
		return err
	}
	aggContextWire, err := cvLeafContextCanonicalBytes(&agg.context)
	if err != nil || !bytes.Equal(contextWire, aggContextWire) {
		return fmt.Errorf("CV-sAPVSS aggregate context mismatch")
	}
	if receipt == nil || receipt.receiverIndex != receiverIndex || !bytes.Equal(receipt.aggregateDigest, agg.digest) {
		return fmt.Errorf("CV-sAPVSS receipt binding mismatch")
	}
	wantFeldman := agg.context.proofProfile == cvLeafStructuralProofProfile
	if receipt.proof.feldman != wantFeldman {
		return fmt.Errorf("CV-sAPVSS receipt mode does not match aggregate profile")
	}
	receiptWire, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		return err
	}
	if !bytes.Equal(receipt.digest, hashBytes([]byte(cvReceiptDomain), receiptWire)) {
		return fmt.Errorf("CV-sAPVSS receipt digest mismatch")
	}
	key := &agg.receivers[receiverIndex-1].receiverPublicKey
	var blindingOpening *bls12381.G1Affine
	if !receipt.proof.feldman {
		blindingOpening = &receipt.blindingOpening
	}
	scalarBase, scalarTarget, blindingBase, blindingTarget, err := cvDLEQTargets(agg, receiverIndex, &receipt.publicScalar, blindingOpening)
	if err != nil {
		return err
	}
	challenge, err := cvDLEQChallengeWithTargets(
		agg, receiverIndex, &receipt.publicScalar, &receipt.blindingOpening, &receipt.proof,
		&scalarBase, &scalarTarget, &blindingBase, &blindingTarget,
	)
	if err != nil {
		return err
	}
	left := cvPointTimes(&genG1, &receipt.proof.z)
	right := cvPointSum(&receipt.proof.tKey, pointPtr(cvPointTimes(key, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("CV-sAPVSS receipt key DLEQ failed")
	}
	left = cvPointTimes(&scalarBase, &receipt.proof.z)
	right = cvPointSum(&receipt.proof.tScalar, pointPtr(cvPointTimes(&scalarTarget, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("CV-sAPVSS receipt scalar DLEQ failed")
	}
	if !receipt.proof.feldman {
		left = cvPointTimes(&blindingBase, &receipt.proof.z)
		right = cvPointSum(&receipt.proof.tBlinding, pointPtr(cvPointTimes(&blindingTarget, &challenge)))
		if !left.Equal(&right) {
			return fmt.Errorf("CV-sAPVSS receipt blinding DLEQ failed")
		}
	} else {
		evaluation := cvEvaluateCommitments(agg.coefficientCommitments, receiverIndex)
		if !receipt.publicScalar.Equal(&evaluation) {
			return fmt.Errorf("CV-sAPVSS Feldman receipt evaluation mismatch")
		}
		return nil
	}
	evaluation := cvEvaluateCommitments(agg.coefficientCommitments, receiverIndex)
	var publicCommitment bls12381.G1Affine
	publicCommitment.Add(&receipt.publicScalar, &receipt.blindingOpening)
	if !publicCommitment.Equal(&evaluation) {
		return fmt.Errorf("CV-sAPVSS receipt evaluation commitment mismatch")
	}
	return nil
}
