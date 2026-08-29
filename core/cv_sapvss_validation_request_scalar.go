package core

import (
	"bytes"
	"fmt"
	"time"
)

const (
	cvValidationRequestWireScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/validation-request-wire"
	cvValidationShareWireScalarDomain   = "ARL-CV-sAPVSS/v2-scalar-group/validation-share-wire"
	cvValidationResultWireScalarDomain  = "ARL-CV-sAPVSS/v2-scalar-group/validation-result-wire"
)

type cvValidationRequestScalar struct {
	Header          cvAggregateHeaderScalar
	Pool            cvPoolScalar
	PoolCert        cvPoolCertificateScalar
	ContributorCoin cvCoinOutputScalar
	SelectedIndices []int
	ARC             cvAPDBLockScalar
}

type cvValidationSignatureScalar struct {
	Statement []byte
	Signature []byte
}

type cvValidationResultScalar struct {
	Statement   []byte
	Certificate cvValidationCertificateScalar
}

func cvValidationRequestScalarCanonicalBytes(request *cvValidationRequestScalar, params cvScalarParams) ([]byte, error) {
	if request == nil || len(request.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 validation request")
	}
	header, err := cvAggregateHeaderScalarCanonicalBytes(&request.Header)
	if err != nil {
		return nil, err
	}
	pool, err := cvPoolScalarCanonicalBytes(&request.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvPoolCertificateScalarCanonicalBytes(&request.PoolCert)
	if err != nil {
		return nil, err
	}
	coin, err := cvCoinOutputScalarCanonicalBytes(&request.ContributorCoin)
	if err != nil {
		return nil, err
	}
	arc, err := cvAPDBLockScalarCanonicalBytes(&request.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationRequestWireScalarDomain))
	_ = cvWriteBytes(&wire, header)
	_ = cvWriteBytes(&wire, pool)
	_ = cvWriteBytes(&wire, poolCert)
	_ = cvWriteBytes(&wire, coin)
	_ = cvWriteUint32(&wire, len(request.SelectedIndices))
	for _, index := range request.SelectedIndices {
		if index < 0 || index >= params.poolSize {
			return nil, fmt.Errorf("invalid CV V2 validation selection index")
		}
		cvWriteUint64(&wire, uint64(index))
	}
	_ = cvWriteBytes(&wire, arc)
	return wire.Bytes(), nil
}

func cvDecodeValidationRequestScalar(wire []byte, params cvScalarParams) (*cvValidationRequestScalar, error) {
	request, _, err := cvDecodeValidationRequestScalarWithCanonical(wire, params)
	return request, err
}

func cvDecodeValidationRequestScalarWithCanonical(wire []byte, params cvScalarParams) (*cvValidationRequestScalar, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationRequestWireScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationRequestWireScalarDomain)) {
		return nil, nil, fmt.Errorf("invalid CV V2 validation request domain")
	}
	nested := make([][]byte, 4)
	for i := range nested {
		nested[i], err = r.bytes(cvMaxNetworkPayloadBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CV V2 validation request field")
		}
	}
	count, err := r.uint32()
	if err != nil || count != params.componentCount {
		return nil, nil, fmt.Errorf("invalid CV V2 validation request selection count")
	}
	selected := make([]int, count)
	for i := range selected {
		value, readErr := r.uint64()
		if readErr != nil || value >= uint64(params.poolSize) {
			return nil, nil, fmt.Errorf("invalid CV V2 validation request selection")
		}
		selected[i] = int(value)
	}
	arcWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 validation request ARC")
	}
	header, err := cvDecodeAggregateHeaderScalar(nested[0])
	if err != nil {
		return nil, nil, err
	}
	pool, err := cvDecodePoolScalar(nested[1], params)
	if err != nil {
		return nil, nil, err
	}
	poolCert, err := cvDecodePoolCertificateScalar(nested[2])
	if err != nil {
		return nil, nil, err
	}
	coin, err := cvDecodeCoinOutputScalar(nested[3])
	if err != nil {
		return nil, nil, err
	}
	arc, err := cvDecodeAPDBLockScalar(arcWire)
	if err != nil {
		return nil, nil, err
	}
	request := &cvValidationRequestScalar{Header: *header, Pool: *pool, PoolCert: *poolCert,
		ContributorCoin: *coin, SelectedIndices: selected, ARC: *arc}
	canonical, err := cvValidationRequestScalarCanonicalBytes(request, params)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, nil, fmt.Errorf("non-canonical CV V2 validation request")
	}
	return request, canonical, nil
}

func cvVerifyValidationRequestPublicScalar(
	request *cvValidationRequestScalar, contextDigest []byte, params cvScalarParams,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) error {
	_, _, err := cvValidateValidationRequestPublicModeScalar(
		request, contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, true,
	)
	return err
}

func cvValidateValidationRequestPublicAfterComponentValidationScalar(
	request *cvValidationRequestScalar, contextDigest []byte, params cvScalarParams,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) ([]byte, time.Duration, error) {
	return cvValidateValidationRequestPublicModeScalar(
		request, contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, false,
	)
}

func cvValidateValidationRequestPublicAfterComponentValidationScalarWithCanonical(
	request *cvValidationRequestScalar, canonical []byte, contextDigest []byte, params cvScalarParams,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) error {
	_, _, err := cvValidateValidationRequestPublicModeScalarWithCanonical(
		request, canonical, 0, contextDigest, params, eligibleProposers,
		apdbSigner, controlSigner, coinSigner, false,
	)
	return err
}

func cvValidateValidationRequestPublicModeScalar(
	request *cvValidationRequestScalar, contextDigest []byte, params cvScalarParams,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
	validateComponents bool,
) ([]byte, time.Duration, error) {
	if request == nil || len(contextDigest) != 32 || len(eligibleProposers) == 0 ||
		!cvScalarSignerHasRole(apdbSigner, cvScalarRoleAPDB) || !cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) ||
		!cvScalarSignerHasRole(coinSigner, cvScalarRoleCoin) {
		return nil, 0, fmt.Errorf("invalid CV V2 validation request context")
	}
	canonicalStarted := time.Now()
	canonical, err := cvValidationRequestScalarCanonicalBytes(request, params)
	canonicalLatency := time.Since(canonicalStarted)
	if err != nil {
		return nil, canonicalLatency, err
	}
	return cvValidateValidationRequestPublicModeScalarWithCanonical(request, canonical, canonicalLatency,
		contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, validateComponents)
}

func cvValidateValidationRequestPublicModeScalarWithCanonical(
	request *cvValidationRequestScalar, canonical []byte, canonicalLatency time.Duration,
	contextDigest []byte, params cvScalarParams,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
	validateComponents bool,
) ([]byte, time.Duration, error) {
	if request == nil || len(canonical) == 0 || len(contextDigest) != 32 || len(eligibleProposers) == 0 ||
		!cvScalarSignerHasRole(apdbSigner, cvScalarRoleAPDB) || !cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) ||
		!cvScalarSignerHasRole(coinSigner, cvScalarRoleCoin) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation request context")
	}
	if _, eligible := eligibleProposers[request.Header.ProposerID]; !eligible ||
		request.Pool.ProposerID != request.Header.ProposerID ||
		!bytes.Equal(request.Header.ContextDigest, contextDigest) ||
		!bytes.Equal(request.Pool.ContextDigest, contextDigest) ||
		!bytes.Equal(request.Header.PoolDigest, request.Pool.Digest) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation proposer, context, or pool")
	}
	if validateComponents {
		for _, component := range request.Pool.Components {
			if err := cvValidateComponentRefScalar(component, apdbSigner); err != nil {
				return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation component: %w", err)
			}
		}
	}
	if err := cvVerifyPoolCertificateScalar(&request.Pool, &request.PoolCert, controlSigner); err != nil {
		return nil, canonicalLatency, err
	}
	invocation, err := cvContributorCoinInvocationScalar(contextDigest, request.Header.ProposerID, request.Pool.Digest)
	if err != nil || cvVerifyCoinOutputScalar(&request.ContributorCoin, invocation, coinSigner) != nil {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation contributor coin")
	}
	want, err := cvSelectedPoolIndicesScalar(params.poolSize, params.componentCount, request.ContributorCoin.Value)
	if err != nil || !equalInts(want, request.SelectedIndices) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation selection")
	}
	selectionDigest, err := cvSelectionDigestScalar(
		&request.ContributorCoin, request.SelectedIndices, params.poolSize, params.componentCount,
	)
	if err != nil || !bytes.Equal(selectionDigest, request.Header.SelectionDigest) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation selection digest")
	}
	if !bytes.Equal(request.ARC.InstanceDigest, request.Header.APDBInstance) ||
		!bytes.Equal(request.ARC.Root, request.Header.APDBRoot) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation ARC binding")
	}
	if err := cvVerifyAPDBLockScalar(&request.ARC, apdbSigner); err != nil {
		return nil, canonicalLatency, err
	}
	return canonical, canonicalLatency, nil
}

func cvValidationSignatureScalarCanonicalBytes(value *cvValidationSignatureScalar) ([]byte, error) {
	if value == nil || len(value.Statement) != 32 || len(value.Signature) == 0 || len(value.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 validation signature")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationShareWireScalarDomain))
	_ = cvWriteBytes(&wire, value.Statement)
	_ = cvWriteBytes(&wire, value.Signature)
	return wire.Bytes(), nil
}

func cvDecodeValidationSignatureScalar(wire []byte) (*cvValidationSignatureScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationShareWireScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationShareWireScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 validation signature domain")
	}
	statement, err := r.bytes(32)
	if err != nil || len(statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 validation signature statement")
	}
	signature, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(signature) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 validation signature bytes")
	}
	value := &cvValidationSignatureScalar{Statement: statement, Signature: signature}
	canonical, err := cvValidationSignatureScalarCanonicalBytes(value)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation signature")
	}
	return value, nil
}

func cvValidationResultScalarCanonicalBytes(result *cvValidationResultScalar, validatorSample []int) ([]byte, error) {
	if result == nil || len(result.Statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 validation result")
	}
	certificate, err := cvValidationCertificateScalarCanonicalBytes(&result.Certificate, validatorSample)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationResultWireScalarDomain))
	_ = cvWriteBytes(&wire, result.Statement)
	_ = cvWriteBytes(&wire, certificate)
	return wire.Bytes(), nil
}

func cvDecodeValidationResultScalar(wire []byte, validatorSample []int) (*cvValidationResultScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationResultWireScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationResultWireScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 validation result domain")
	}
	statement, err := r.bytes(32)
	if err != nil || len(statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 validation result statement")
	}
	certificateWire, err := r.bytes(cvMaxComponentSignatureBytes + 256)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 validation result certificate")
	}
	certificate, err := cvDecodeValidationCertificateScalar(certificateWire, validatorSample)
	if err != nil {
		return nil, err
	}
	result := &cvValidationResultScalar{Statement: statement, Certificate: *certificate}
	canonical, err := cvValidationResultScalarCanonicalBytes(result, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation result")
	}
	return result, nil
}
