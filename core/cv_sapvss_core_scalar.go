package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLeafContextWireDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/leaf-context"
	cvCoreProofWireDomainScalar   = "ARL-CV-sAPVSS/v2-scalar-group/core-proof"
	cvCoreProofChallengeScalar    = "ARL-CV-sAPVSS/v2-scalar-group/core-proof/challenge"
)

type cvLeafContextScalar struct {
	SID                    string
	Epoch                  uint64
	OldRoster              []int
	NewRoster              []int
	ReceiverRegistryDigest []byte
	SharingDegree          int
	Profile                cvChunkProfile
}

type cvCoreProofScalar struct {
	NonceCommitments  []bls12381.G1Affine
	ScalarResponses   []fr.Element
	BlindingResponses []fr.Element
}

func cvValidateLeafContextScalar(context *cvLeafContextScalar) error {
	if context == nil || context.SID == "" || len(context.SID) > cvMaxNetworkEnvelopeSIDBytes ||
		context.Epoch == 0 || len(context.ReceiverRegistryDigest) != 32 ||
		len(context.OldRoster) == 0 || len(context.NewRoster) == 0 ||
		!equalInts(context.OldRoster, sortedUnique(context.OldRoster)) ||
		!equalInts(context.NewRoster, sortedUnique(context.NewRoster)) ||
		context.SharingDegree < 0 || context.SharingDegree >= len(context.NewRoster) {
		return fmt.Errorf("invalid CV V2 leaf context")
	}
	if _, _, _, err := cvProfile(context.Profile); err != nil {
		return fmt.Errorf("invalid CV V2 leaf context profile: %w", err)
	}
	for _, roster := range [][]int{context.OldRoster, context.NewRoster} {
		for _, member := range roster {
			if member < 0 {
				return fmt.Errorf("invalid CV V2 leaf context member")
			}
		}
	}
	return nil
}

func cvLeafContextScalarCanonicalBytes(context *cvLeafContextScalar) ([]byte, error) {
	if err := cvValidateLeafContextScalar(context); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLeafContextWireDomainScalar))
	_ = cvWriteBytes(&wire, []byte(cvLeafGroupID))
	_ = cvWriteBytes(&wire, []byte(context.SID))
	cvWriteUint64(&wire, context.Epoch)
	if err := cvWriteUint32(&wire, len(context.OldRoster)); err != nil {
		return nil, err
	}
	for _, member := range context.OldRoster {
		cvWriteUint64(&wire, uint64(member))
	}
	if err := cvWriteUint32(&wire, len(context.NewRoster)); err != nil {
		return nil, err
	}
	for _, member := range context.NewRoster {
		cvWriteUint64(&wire, uint64(member))
	}
	_ = cvWriteBytes(&wire, context.ReceiverRegistryDigest)
	if err := cvWriteUint32(&wire, context.SharingDegree); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(context.Profile.chunkBits))
	if err := cvWriteUint32(&wire, context.Profile.maxComponents); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeLeafContextScalar(wire []byte) (*cvLeafContextScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLeafContextWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafContextWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 leaf context domain")
	}
	group, err := r.bytes(len(cvLeafGroupID))
	if err != nil || !bytes.Equal(group, []byte(cvLeafGroupID)) {
		return nil, fmt.Errorf("invalid CV V2 leaf context group")
	}
	sid, err := r.bytes(cvMaxNetworkEnvelopeSIDBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf context SID")
	}
	epoch, err := r.uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf context epoch")
	}
	oldRoster, err := cvDecodeRosterScalar(r)
	if err != nil {
		return nil, err
	}
	newRoster, err := cvDecodeRosterScalar(r)
	if err != nil {
		return nil, err
	}
	registryDigest, err := r.bytes(32)
	if err != nil || len(registryDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 receiver registry digest")
	}
	degree, err := r.uint32()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 sharing degree")
	}
	chunkBits, err := r.uint64()
	if err != nil || chunkBits > uint64(^uint(0)) {
		return nil, fmt.Errorf("invalid CV V2 chunk bits")
	}
	maxComponents, err := r.uint32()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 chunk profile")
	}
	context := &cvLeafContextScalar{
		SID: string(sid), Epoch: epoch, OldRoster: oldRoster, NewRoster: newRoster,
		ReceiverRegistryDigest: registryDigest, SharingDegree: degree,
		Profile: cvChunkProfile{chunkBits: uint(chunkBits), maxComponents: maxComponents},
	}
	canonical, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 leaf context")
	}
	return context, nil
}

func cvLeafContextDigestScalar(context *cvLeafContextScalar) ([]byte, error) {
	wire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvLeafContextWireDomainScalar), wire), nil
}

func cvProveCoreScalar(
	context *cvLeafContextScalar, dealerID int, scalarCoefficients, blindingCoefficients []fr.Element,
) ([]bls12381.G1Affine, *cvCoreProofScalar, error) {
	if err := cvValidateLeafContextScalar(context); err != nil || dealerID < 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 core proof witness")
	}
	count := context.SharingDegree + 1
	if len(scalarCoefficients) != count || len(blindingCoefficients) != count {
		return nil, nil, fmt.Errorf("invalid CV V2 core proof witness")
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	commitments := make([]bls12381.G1Affine, count)
	proof := &cvCoreProofScalar{
		NonceCommitments: make([]bls12381.G1Affine, count),
		ScalarResponses:  make([]fr.Element, count), BlindingResponses: make([]fr.Element, count),
	}
	scalarNonces := make([]fr.Element, count)
	blindingNonces := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		commitments[i] = cvPointBaseAndTimes(&scalarCoefficients[i], &h, &blindingCoefficients[i])
		if _, err := scalarNonces[i].SetRandom(); err != nil {
			return nil, nil, err
		}
		if _, err := blindingNonces[i].SetRandom(); err != nil {
			return nil, nil, err
		}
		proof.NonceCommitments[i] = cvPointBaseAndTimes(&scalarNonces[i], &h, &blindingNonces[i])
	}
	challenge, err := cvCoreProofChallengeScalarAfterValidationScalar(
		context, dealerID, commitments, proof.NonceCommitments,
	)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < count; i++ {
		proof.ScalarResponses[i].Mul(&challenge, &scalarCoefficients[i]).Add(&proof.ScalarResponses[i], &scalarNonces[i])
		proof.BlindingResponses[i].Mul(&challenge, &blindingCoefficients[i]).Add(&proof.BlindingResponses[i], &blindingNonces[i])
	}
	return commitments, proof, nil
}

func cvVerifyCoreScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, proof *cvCoreProofScalar,
) error {
	return cvVerifyCoreModeScalar(context, dealerID, commitments, proof, true)
}

func cvVerifyCoreAfterPointDecodingScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, proof *cvCoreProofScalar,
) error {
	return cvVerifyCoreModeScalar(context, dealerID, commitments, proof, false)
}

func cvVerifyCoreModeScalar(
	context *cvLeafContextScalar, dealerID int, commitments []bls12381.G1Affine, proof *cvCoreProofScalar,
	validatePoints bool,
) error {
	count := 0
	if context != nil {
		count = context.SharingDegree + 1
	}
	if err := cvValidateLeafContextScalar(context); err != nil || dealerID < 0 || proof == nil ||
		len(commitments) != count || len(proof.NonceCommitments) != count ||
		len(proof.ScalarResponses) != count || len(proof.BlindingResponses) != count {
		return fmt.Errorf("invalid CV V2 core proof")
	}
	if validatePoints {
		for i := 0; i < count; i++ {
			if !cvValidG1(&commitments[i], true) || !cvValidG1(&proof.NonceCommitments[i], true) {
				return fmt.Errorf("invalid CV V2 core proof point")
			}
		}
	}
	challenge, err := cvCoreProofChallengeScalarAfterValidationScalar(
		context, dealerID, commitments, proof.NonceCommitments,
	)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		left := cvPointBaseAndTimes(&proof.ScalarResponses[i], &h, &proof.BlindingResponses[i])
		right := cvPointSum(&proof.NonceCommitments[i], pointPtr(cvPointTimes(&commitments[i], &challenge)))
		if !left.Equal(&right) {
			return fmt.Errorf("invalid CV V2 core proof equation %d", i)
		}
	}
	return nil
}

func cvCoreProofChallengeScalarAfterValidationScalar(
	context *cvLeafContextScalar, dealerID int, commitments, nonceCommitments []bls12381.G1Affine,
) (fr.Element, error) {
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil || dealerID < 0 || len(commitments) == 0 || len(commitments) != len(nonceCommitments) {
		return fr.Element{}, fmt.Errorf("invalid verified CV V2 core proof challenge")
	}
	return cvCoreProofChallengeScalarModeScalar(contextWire, dealerID, commitments, nonceCommitments, false)
}

func cvCoreProofChallengeScalarModeScalar(
	contextWire []byte, dealerID int, commitments, nonceCommitments []bls12381.G1Affine,
	validatePoints bool,
) (fr.Element, error) {
	var statement bytes.Buffer
	_ = cvWriteBytes(&statement, contextWire)
	cvWriteUint64(&statement, uint64(dealerID))
	if err := cvWritePointVectorMode(&statement, commitments, validatePoints); err != nil {
		return fr.Element{}, err
	}
	if err := cvWritePointVectorMode(&statement, nonceCommitments, validatePoints); err != nil {
		return fr.Element{}, err
	}
	return cvHashToFr(cvCoreProofChallengeScalar, statement.Bytes())
}

func cvCoreProofScalarCanonicalBytes(proof *cvCoreProofScalar, coefficientCount int) ([]byte, error) {
	return cvCoreProofScalarCanonicalBytesMode(proof, coefficientCount, true)
}

func cvCoreProofScalarCanonicalBytesAfterValidation(proof *cvCoreProofScalar, coefficientCount int) ([]byte, error) {
	return cvCoreProofScalarCanonicalBytesMode(proof, coefficientCount, false)
}

func cvCoreProofScalarCanonicalBytesMode(
	proof *cvCoreProofScalar, coefficientCount int, validatePoints bool,
) ([]byte, error) {
	if proof == nil || coefficientCount <= 0 || len(proof.NonceCommitments) != coefficientCount ||
		len(proof.ScalarResponses) != coefficientCount || len(proof.BlindingResponses) != coefficientCount {
		return nil, fmt.Errorf("invalid CV V2 core proof wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCoreProofWireDomainScalar))
	if err := cvWritePointVectorMode(&wire, proof.NonceCommitments, validatePoints); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.ScalarResponses); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.BlindingResponses); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeCoreProofScalar(wire []byte, coefficientCount int) (*cvCoreProofScalar, error) {
	return cvDecodeCoreProofScalarSidechannel(wire, coefficientCount, nil)
}

func cvDecodeCoreProofScalarSidechannel(
	wire []byte, coefficientCount int, side *cvDecodeSidechannelScalar,
) (*cvCoreProofScalar, error) {
	if coefficientCount <= 0 {
		return nil, fmt.Errorf("invalid CV V2 core proof coefficient count")
	}
	r := newCVWireReaderSide(wire, side)
	domain, err := r.bytes(len(cvCoreProofWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvCoreProofWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 core proof domain")
	}
	nonceCommitments, err := cvReadExactPointVectorDeferred(r, coefficientCount, "V2 core nonce commitments")
	if err != nil {
		return nil, err
	}
	scalarResponses, err := cvReadExactScalarVectorScalar(r, coefficientCount)
	if err != nil {
		return nil, err
	}
	blindingResponses, err := cvReadExactScalarVectorScalar(r, coefficientCount)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 core proof responses")
	}
	proof := &cvCoreProofScalar{
		NonceCommitments: nonceCommitments, ScalarResponses: scalarResponses, BlindingResponses: blindingResponses,
	}
	if err := r.assertDecodedSubgroup(); err != nil {
		return nil, fmt.Errorf("invalid CV V2 core proof point: %w", err)
	}
	canonical, err := cvCoreProofScalarCanonicalBytes(proof, coefficientCount)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 core proof")
	}
	return proof, nil
}

func cvDecodeRosterScalar(r *cvWireReader) ([]int, error) {
	count, err := r.uint32()
	if err != nil || count <= 0 || count > 1<<20 {
		return nil, fmt.Errorf("invalid CV V2 roster count")
	}
	roster := make([]int, count)
	for i := range roster {
		member, err := r.uint64()
		if err != nil || member > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid CV V2 roster member")
		}
		roster[i] = int(member)
	}
	return roster, nil
}

func cvReadExactScalarVectorScalar(r *cvWireReader, count int) ([]fr.Element, error) {
	got, err := r.uint32()
	if err != nil || got != count {
		return nil, fmt.Errorf("invalid CV V2 scalar vector count")
	}
	out := make([]fr.Element, count)
	for i := range out {
		out[i], err = r.scalar()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
