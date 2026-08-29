package core

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const (
	cvValidationStatementScalarDomain   = "ARL-CV-sAPVSS/v2-scalar-group/validation-statement"
	cvValidationCertificateScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/validation-certificate"
)

// cvValidationCertificateScalar certifies an aggregate digest. Its bitmap is
// indexed by the deterministic validator sample.
type cvValidationCertificateScalar struct {
	SignerBitmap       []byte
	AggregateSignature []byte
	// canonicalWire is set by the strict decoder after validating the wire.
	// Reusing it avoids reparsing the aggregate signature in later predicates.
	canonicalWire []byte
}

type cvValidationBuildTimingsScalar struct {
	IndividualVerify time.Duration
	AggregateVerify  time.Duration
}

func cvValidationStatementScalar(validatorSample []int, header *cvAggregateHeaderScalar) ([]byte, error) {
	if !cvDistinctNonNegativeIDs(validatorSample) || len(validatorSample) == 0 {
		return nil, fmt.Errorf("invalid CV V2 validation statement")
	}
	headerWire, err := cvAggregateHeaderScalarCanonicalBytes(header)
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
	return hashBytes([]byte(cvValidationStatementScalarDomain), wire.Bytes()), nil
}

func cvValidationCertificateScalarCanonicalBytes(certificate *cvValidationCertificateScalar, validatorSample []int) ([]byte, error) {
	if certificate == nil || len(validatorSample) == 0 || !cvDistinctNonNegativeIDs(validatorSample) ||
		len(certificate.SignerBitmap) != cvValidationBitmapBytesScalar(len(validatorSample)) ||
		!cvValidationBitmapHighBitsZeroScalar(certificate.SignerBitmap, len(validatorSample)) ||
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
	_ = cvWriteBytes(&wire, []byte(cvValidationCertificateScalarDomain))
	_ = cvWriteBytes(&wire, certificate.SignerBitmap)
	_ = cvWriteBytes(&wire, certificate.AggregateSignature)
	return wire.Bytes(), nil
}

func cvDecodeValidationCertificateScalar(wire []byte, validatorSample []int) (*cvValidationCertificateScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationCertificateScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationCertificateScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 validation certificate domain")
	}
	bitmap, err := r.bytes(cvValidationBitmapBytesScalar(len(validatorSample)))
	if err != nil || len(bitmap) != cvValidationBitmapBytesScalar(len(validatorSample)) {
		return nil, fmt.Errorf("invalid CV V2 validation certificate bitmap")
	}
	signature, err := r.bytes(bls12381.SizeOfG1AffineCompressed)
	if err != nil || len(signature) != bls12381.SizeOfG1AffineCompressed || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 validation certificate signature")
	}
	certificate := &cvValidationCertificateScalar{SignerBitmap: bitmap, AggregateSignature: signature}
	canonical, err := cvValidationCertificateScalarCanonicalBytes(certificate, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation certificate")
	}
	certificate.canonicalWire = canonical
	return certificate, nil
}

func cvBuildValidationCertificateScalar(
	header *cvAggregateHeaderScalar, validatorSample []int, quorum int,
	signatures map[int][]byte, material *cvValidatorKeyMaterialScalar,
) (*cvValidationCertificateScalar, error) {
	certificate, _, err := cvBuildValidationCertificateModeScalar(
		header, validatorSample, quorum, signatures, material, true,
	)
	return certificate, err
}

func cvBuildValidationCertificateModeScalar(
	header *cvAggregateHeaderScalar, validatorSample []int, quorum int,
	signatures map[int][]byte, material *cvValidatorKeyMaterialScalar, verifyIndividuals bool,
) (*cvValidationCertificateScalar, cvValidationBuildTimingsScalar, error) {
	var timings cvValidationBuildTimingsScalar
	if material == nil || quorum <= 0 || quorum > len(validatorSample) || len(signatures) < quorum ||
		!cvValidValidatorSampleScalar(validatorSample, material) {
		return nil, timings, fmt.Errorf("invalid CV V2 validation certificate construction")
	}
	statement, err := cvValidationStatementScalar(validatorSample, header)
	if err != nil {
		return nil, timings, err
	}
	bitmap := make([]byte, cvValidationBitmapBytesScalar(len(validatorSample)))
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
			valid := cvVerifyValidatorSignatureScalar(
				&material.publicKeys[material.memberIndex[member]],
				cvValidationCertificateScalarDomain, statement, signature,
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
	certificate := &cvValidationCertificateScalar{
		SignerBitmap: bitmap,
		AggregateSignature: func() []byte {
			encoded := aggregate.Bytes()
			return append([]byte(nil), encoded[:]...)
		}(),
	}
	started := time.Now()
	verifyErr := cvVerifyValidationCertificateScalar(certificate, header, validatorSample, quorum, material)
	timings.AggregateVerify = time.Since(started)
	if verifyErr != nil {
		return nil, timings, verifyErr
	}
	return certificate, timings, nil
}

func cvVerifyValidationCertificateScalar(certificate *cvValidationCertificateScalar, header *cvAggregateHeaderScalar, validatorSample []int, quorum int, material *cvValidatorKeyMaterialScalar) error {
	statement, err := cvValidationStatementScalar(validatorSample, header)
	if err != nil {
		return err
	}
	return cvVerifyValidationCertificateScalarWithStatement(certificate, statement, validatorSample, quorum, material)
}

// cvVerifyValidationCertificateScalarWithStatement is used when the caller has
// already authenticated and cached the statement for this request. It keeps
// all certificate/bitmap/pairing checks while avoiding a second header encode.
func cvVerifyValidationCertificateScalarWithStatement(certificate *cvValidationCertificateScalar, statement []byte, validatorSample []int, quorum int, material *cvValidatorKeyMaterialScalar) error {
	if material == nil || quorum <= 0 || quorum > len(validatorSample) || !cvValidValidatorSampleScalar(validatorSample, material) {
		return fmt.Errorf("invalid CV V2 validation verification input")
	}
	if len(statement) != 32 {
		return fmt.Errorf("invalid CV V2 validation statement")
	}
	if _, err := cvValidationCertificateScalarCanonicalBytes(certificate, validatorSample); err != nil {
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
	hashPoint, err := bls12381.HashToG1(domainDigest(cvValidationCertificateScalarDomain, statement), []byte(cvValidationCertificateScalarDomain))
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

func cvSignValidationScalar(memberID int, header *cvAggregateHeaderScalar, validatorSample []int, material *cvValidatorKeyMaterialScalar) ([]byte, error) {
	if material == nil {
		return nil, fmt.Errorf("nil CV V2 validator material")
	}
	secret, ok := material.localSecrets[memberID]
	if !ok {
		return nil, fmt.Errorf("CV V2 validator has no local signing secret")
	}
	if !cvValidValidatorSampleScalar(validatorSample, material) {
		return nil, fmt.Errorf("invalid CV V2 validator sample")
	}
	memberPresent := false
	for _, member := range validatorSample {
		memberPresent = memberPresent || member == memberID
	}
	if !memberPresent {
		return nil, fmt.Errorf("CV V2 signer is outside validator sample")
	}
	statement, err := cvValidationStatementScalar(validatorSample, header)
	if err != nil {
		return nil, err
	}
	return cvSignValidatorScalar(secret, cvValidationCertificateScalarDomain, statement)
}

func cvValidationBitmapBytesScalar(sampleSize int) int {
	if sampleSize <= 0 {
		return 0
	}
	return (sampleSize + 7) / 8
}

func cvValidationBitmapHighBitsZeroScalar(bitmap []byte, sampleSize int) bool {
	if sampleSize <= 0 || len(bitmap) != cvValidationBitmapBytesScalar(sampleSize) {
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

func cvValidValidatorSampleScalar(sample []int, material *cvValidatorKeyMaterialScalar) bool {
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
