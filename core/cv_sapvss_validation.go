package core

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvValidationStatementV2Domain   = "ARL-CV-sAPVSS/v2-scalar-group/validation-statement"
	cvValidationCertificateV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/validation-certificate"
)

// cvValidationCertificateV2 certifies one aggregate object digest. The
// bitmap is indexed by the deterministic validator sample, never by the full
// old-committee roster. The sample is derived from the eligibility coin and
// supplied again by the verifier.
type cvValidationCertificateV2 struct {
	SignerBitmap       []byte
	AggregateSignature []byte
	// canonicalWire is set by the strict decoder after validating the wire.
	// Reusing it avoids reparsing the aggregate signature in later predicates.
	canonicalWire []byte
}

type cvValidationBuildTimingsV2 struct {
	IndividualVerify time.Duration
	AggregateVerify  time.Duration
}

func cvValidationStatementV2(validatorSample []int, header *cvAggregateHeaderV2) ([]byte, error) {
	if !cvDistinctNonNegativeIDs(validatorSample) || len(validatorSample) == 0 {
		return nil, fmt.Errorf("invalid CV V2 validation statement")
	}
	headerWire, err := cvAggregateHeaderV2CanonicalBytes(header)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteUint32(&wire, len(validatorSample)); err != nil {
		return nil, err
	}
	for _, member := range validatorSample {
		cvWriteUint64(&wire, uint64(member))
	}
	_ = cvWriteBytes(&wire, headerWire)
	return hashBytes([]byte(cvValidationStatementV2Domain), wire.Bytes()), nil
}

func cvValidationCertificateV2CanonicalBytes(certificate *cvValidationCertificateV2, validatorSample []int) ([]byte, error) {
	if certificate == nil || len(validatorSample) == 0 || !cvDistinctNonNegativeIDs(validatorSample) ||
		len(certificate.SignerBitmap) != cvValidationBitmapBytesV2(len(validatorSample)) ||
		!cvValidationBitmapHighBitsZeroV2(certificate.SignerBitmap, len(validatorSample)) ||
		len(certificate.AggregateSignature) != bls12381.SizeOfG1AffineCompressed {
		return nil, fmt.Errorf("invalid CV V2 validation certificate")
	}
	if len(certificate.canonicalWire) != 0 {
		return certificate.canonicalWire, nil
	}
	var signature bls12381.G1Affine
	consumed, err := signature.SetBytes(certificate.AggregateSignature)
	if err != nil || consumed != len(certificate.AggregateSignature) || !cvValidG1(&signature, false) {
		return nil, fmt.Errorf("invalid CV V2 validation aggregate signature")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationCertificateV2Domain))
	_ = cvWriteBytes(&wire, certificate.SignerBitmap)
	_ = cvWriteBytes(&wire, certificate.AggregateSignature)
	return wire.Bytes(), nil
}

func cvDecodeValidationCertificateV2(wire []byte, validatorSample []int) (*cvValidationCertificateV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationCertificateV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationCertificateV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 validation certificate domain")
	}
	bitmap, err := r.bytes(cvValidationBitmapBytesV2(len(validatorSample)))
	if err != nil || len(bitmap) != cvValidationBitmapBytesV2(len(validatorSample)) {
		return nil, fmt.Errorf("invalid CV V2 validation certificate bitmap")
	}
	signature, err := r.bytes(bls12381.SizeOfG1AffineCompressed)
	if err != nil || len(signature) != bls12381.SizeOfG1AffineCompressed || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 validation certificate signature")
	}
	certificate := &cvValidationCertificateV2{SignerBitmap: bitmap, AggregateSignature: signature}
	canonical, err := cvValidationCertificateV2CanonicalBytes(certificate, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation certificate")
	}
	certificate.canonicalWire = canonical
	return certificate, nil
}

func cvBuildValidationCertificateV2(
	header *cvAggregateHeaderV2, validatorSample []int, quorum int,
	signatures map[int][]byte, material *cvValidatorKeyMaterialV2,
) (*cvValidationCertificateV2, error) {
	certificate, _, err := cvBuildValidationCertificateModeV2(
		header, validatorSample, quorum, signatures, material, true,
	)
	return certificate, err
}

func cvBuildValidationCertificateModeV2(
	header *cvAggregateHeaderV2, validatorSample []int, quorum int,
	signatures map[int][]byte, material *cvValidatorKeyMaterialV2, verifyIndividuals bool,
) (*cvValidationCertificateV2, cvValidationBuildTimingsV2, error) {
	var timings cvValidationBuildTimingsV2
	if material == nil || quorum <= 0 || quorum > len(validatorSample) || len(signatures) < quorum ||
		!cvValidValidatorSampleV2(validatorSample, material) {
		return nil, timings, fmt.Errorf("invalid CV V2 validation certificate construction")
	}
	statement, err := cvValidationStatementV2(validatorSample, header)
	if err != nil {
		return nil, timings, err
	}
	bitmap := make([]byte, cvValidationBitmapBytesV2(len(validatorSample)))
	var aggregate bls12381.G1Affine
	aggregate.ScalarMultiplication(&genG1, big.NewInt(0))
	signerCount := 0
	for index, member := range validatorSample {
		signature, ok := signatures[member]
		if !ok {
			continue
		}
		if verifyIndividuals {
			started := time.Now()
			valid := cvVerifyValidatorSignatureV2(
				&material.publicKeys[material.memberIndex[member]],
				cvValidationCertificateV2Domain, statement, signature,
			)
			timings.IndividualVerify += time.Since(started)
			if !valid {
				return nil, timings, fmt.Errorf("invalid CV V2 validator signature")
			}
		}
		var point bls12381.G1Affine
		_, _ = point.SetBytes(signature)
		aggregate.Add(&aggregate, &point)
		bitmap[index/8] |= 1 << uint(index%8)
		signerCount++
	}
	if signerCount < quorum || signerCount != len(signatures) {
		return nil, timings, fmt.Errorf("insufficient or non-sample CV V2 validator signatures")
	}
	certificate := &cvValidationCertificateV2{
		SignerBitmap: bitmap,
		AggregateSignature: func() []byte {
			encoded := aggregate.Bytes()
			return append([]byte(nil), encoded[:]...)
		}(),
	}
	started := time.Now()
	verifyErr := cvVerifyValidationCertificateV2(certificate, header, validatorSample, quorum, material)
	timings.AggregateVerify = time.Since(started)
	if verifyErr != nil {
		return nil, timings, verifyErr
	}
	return certificate, timings, nil
}

func cvVerifyValidationCertificateV2(certificate *cvValidationCertificateV2, header *cvAggregateHeaderV2, validatorSample []int, quorum int, material *cvValidatorKeyMaterialV2) error {
	statement, err := cvValidationStatementV2(validatorSample, header)
	if err != nil {
		return err
	}
	return cvVerifyValidationCertificateV2WithStatement(certificate, statement, validatorSample, quorum, material)
}

// cvVerifyValidationCertificateV2WithStatement is used when the caller has
// already authenticated and cached the statement for this request. It keeps
// all certificate/bitmap/pairing checks while avoiding a second header encode.
func cvVerifyValidationCertificateV2WithStatement(certificate *cvValidationCertificateV2, statement []byte, validatorSample []int, quorum int, material *cvValidatorKeyMaterialV2) error {
	if material == nil || quorum <= 0 || quorum > len(validatorSample) || !cvValidValidatorSampleV2(validatorSample, material) {
		return fmt.Errorf("invalid CV V2 validation verification input")
	}
	if len(statement) != 32 {
		return fmt.Errorf("invalid CV V2 validation statement")
	}
	if _, err := cvValidationCertificateV2CanonicalBytes(certificate, validatorSample); err != nil {
		return err
	}
	signerCount := 0
	var aggregatePublic bls12381.G2Affine
	aggregatePublic.ScalarMultiplication(&genG2, big.NewInt(0))
	for index, member := range validatorSample {
		if certificate.SignerBitmap[index/8]&(1<<uint(index%8)) == 0 {
			continue
		}
		aggregatePublic.Add(&aggregatePublic, &material.publicKeys[material.memberIndex[member]])
		signerCount++
	}
	if signerCount < quorum || aggregatePublic.IsInfinity() {
		return fmt.Errorf("insufficient CV V2 validation certificate signers")
	}
	var signature bls12381.G1Affine
	_, _ = signature.SetBytes(certificate.AggregateSignature)
	hashPoint, err := bls12381.HashToG1(domainDigest(cvValidationCertificateV2Domain, statement), []byte(cvValidationCertificateV2Domain))
	if err != nil {
		return err
	}
	var negative bls12381.G2Affine
	negative.Neg(&aggregatePublic)
	ok, pairingErr := bls12381.PairingCheck(
		[]bls12381.G1Affine{signature, hashPoint},
		[]bls12381.G2Affine{genG2, negative},
	)
	if pairingErr != nil || !ok {
		return fmt.Errorf("invalid CV V2 validation certificate aggregate signature")
	}
	return nil
}

func cvSignValidationV2(memberID int, header *cvAggregateHeaderV2, validatorSample []int, material *cvValidatorKeyMaterialV2) ([]byte, error) {
	if material == nil {
		return nil, fmt.Errorf("nil CV V2 validator material")
	}
	secret, ok := material.localSecrets[memberID]
	if !ok {
		return nil, fmt.Errorf("CV V2 validator has no local signing secret")
	}
	if !cvValidValidatorSampleV2(validatorSample, material) {
		return nil, fmt.Errorf("invalid CV V2 validator sample")
	}
	memberPresent := false
	for _, member := range validatorSample {
		memberPresent = memberPresent || member == memberID
	}
	if !memberPresent {
		return nil, fmt.Errorf("CV V2 signer is outside validator sample")
	}
	statement, err := cvValidationStatementV2(validatorSample, header)
	if err != nil {
		return nil, err
	}
	return cvSignValidatorV2(secret, cvValidationCertificateV2Domain, statement)
}

func cvValidationBitmapBytesV2(sampleSize int) int {
	if sampleSize <= 0 {
		return 0
	}
	return (sampleSize + 7) / 8
}

func cvValidationBitmapHighBitsZeroV2(bitmap []byte, sampleSize int) bool {
	if sampleSize <= 0 || len(bitmap) != cvValidationBitmapBytesV2(sampleSize) {
		return false
	}
	unused := len(bitmap)*8 - sampleSize
	return unused == 0 || bitmap[len(bitmap)-1]&byte(0xff<<uint(8-unused)) == 0
}

func cvDistinctNonNegativeIDs(ids []int) bool {
	seen := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		if id < 0 {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func cvValidValidatorSampleV2(sample []int, material *cvValidatorKeyMaterialV2) bool {
	if len(sample) == 0 || material == nil || !cvDistinctNonNegativeIDs(sample) {
		return false
	}
	for _, member := range sample {
		if _, ok := material.memberIndex[member]; !ok {
			return false
		}
	}
	return true
}
