package core

import (
	"bytes"
	"fmt"
	"time"
)

const (
	cvValidationRequestWireV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/validation-request-wire"
	cvValidationShareWireV2Domain   = "ARL-CV-sAPVSS/v2-scalar-group/validation-share-wire"
	cvValidationResultWireV2Domain  = "ARL-CV-sAPVSS/v2-scalar-group/validation-result-wire"
)

type cvValidationRequestV2 struct {
	Header          cvAggregateHeaderV2
	Pool            cvPoolV2
	PoolCert        cvPoolCertificateV2
	ContributorCoin cvCoinOutputV2
	SelectedIndices []int
	ARC             cvAPDBLockV2
}

type cvValidationSignatureV2 struct {
	Statement []byte
	Signature []byte
}

type cvValidationResultV2 struct {
	Statement   []byte
	Certificate cvValidationCertificateV2
}

func cvValidationRequestV2CanonicalBytes(request *cvValidationRequestV2, params cvV2Params) ([]byte, error) {
	if request == nil || len(request.SelectedIndices) != params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 validation request")
	}
	header, err := cvAggregateHeaderV2CanonicalBytes(&request.Header)
	if err != nil {
		return nil, err
	}
	pool, err := cvPoolV2CanonicalBytes(&request.Pool, params)
	if err != nil {
		return nil, err
	}
	poolCert, err := cvPoolCertificateV2CanonicalBytes(&request.PoolCert)
	if err != nil {
		return nil, err
	}
	coin, err := cvCoinOutputV2CanonicalBytes(&request.ContributorCoin)
	if err != nil {
		return nil, err
	}
	arc, err := cvAPDBLockV2CanonicalBytes(&request.ARC)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationRequestWireV2Domain))
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

func cvDecodeValidationRequestV2(wire []byte, params cvV2Params) (*cvValidationRequestV2, error) {
	request, _, err := cvDecodeValidationRequestV2WithCanonical(wire, params)
	return request, err
}

func cvDecodeValidationRequestV2WithCanonical(wire []byte, params cvV2Params) (*cvValidationRequestV2, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationRequestWireV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationRequestWireV2Domain)) {
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
	header, err := cvDecodeAggregateHeaderV2(nested[0])
	if err != nil {
		return nil, nil, err
	}
	pool, err := cvDecodePoolV2(nested[1], params)
	if err != nil {
		return nil, nil, err
	}
	poolCert, err := cvDecodePoolCertificateV2(nested[2])
	if err != nil {
		return nil, nil, err
	}
	coin, err := cvDecodeCoinOutputV2(nested[3])
	if err != nil {
		return nil, nil, err
	}
	arc, err := cvDecodeAPDBLockV2(arcWire)
	if err != nil {
		return nil, nil, err
	}
	request := &cvValidationRequestV2{Header: *header, Pool: *pool, PoolCert: *poolCert,
		ContributorCoin: *coin, SelectedIndices: selected, ARC: *arc}
	canonical, err := cvValidationRequestV2CanonicalBytes(request, params)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, nil, fmt.Errorf("non-canonical CV V2 validation request")
	}
	return request, canonical, nil
}

func cvVerifyValidationRequestPublicV2(
	request *cvValidationRequestV2, contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) error {
	_, _, err := cvValidateValidationRequestPublicModeV2(
		request, contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, true,
	)
	return err
}

func cvVerifyValidationRequestPublicAfterComponentValidationV2(
	request *cvValidationRequestV2, contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) error {
	_, _, err := cvValidateValidationRequestPublicModeV2(
		request, contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, false,
	)
	return err
}

func cvValidateValidationRequestPublicAfterComponentValidationV2(
	request *cvValidationRequestV2, contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) ([]byte, time.Duration, error) {
	return cvValidateValidationRequestPublicModeV2(
		request, contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, false,
	)
}

func cvValidateValidationRequestPublicAfterComponentValidationV2WithCanonical(
	request *cvValidationRequestV2, canonical []byte, contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) error {
	_, _, err := cvValidateValidationRequestPublicModeV2WithCanonical(
		request, canonical, 0, contextDigest, params, eligibleProposers,
		apdbSigner, controlSigner, coinSigner, false,
	)
	return err
}

func cvValidateValidationRequestPublicModeV2(
	request *cvValidationRequestV2, contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
	validateComponents bool,
) ([]byte, time.Duration, error) {
	if request == nil || len(contextDigest) != 32 || len(eligibleProposers) == 0 ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) || !cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!cvV2SignerHasRole(coinSigner, cvV2RoleCoin) {
		return nil, 0, fmt.Errorf("invalid CV V2 validation request context")
	}
	canonicalStarted := time.Now()
	canonical, err := cvValidationRequestV2CanonicalBytes(request, params)
	canonicalLatency := time.Since(canonicalStarted)
	if err != nil {
		return nil, canonicalLatency, err
	}
	return cvValidateValidationRequestPublicModeV2WithCanonical(request, canonical, canonicalLatency,
		contextDigest, params, eligibleProposers, apdbSigner, controlSigner, coinSigner, validateComponents)
}

func cvValidateValidationRequestPublicModeV2WithCanonical(
	request *cvValidationRequestV2, canonical []byte, canonicalLatency time.Duration,
	contextDigest []byte, params cvV2Params,
	eligibleProposers map[int]struct{}, apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
	validateComponents bool,
) ([]byte, time.Duration, error) {
	if request == nil || len(canonical) == 0 || len(contextDigest) != 32 || len(eligibleProposers) == 0 ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) || !cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!cvV2SignerHasRole(coinSigner, cvV2RoleCoin) {
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
			if err := cvValidateComponentRefV2(component, apdbSigner); err != nil {
				return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation component: %w", err)
			}
		}
	}
	if err := cvVerifyPoolCertificateV2(&request.Pool, &request.PoolCert, controlSigner); err != nil {
		return nil, canonicalLatency, err
	}
	invocation, err := cvContributorCoinInvocationV2(contextDigest, request.Header.ProposerID, request.Pool.Digest)
	if err != nil || cvVerifyCoinOutputV2(&request.ContributorCoin, invocation, coinSigner) != nil {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation contributor coin")
	}
	want, err := cvSelectedPoolIndicesV2(params.poolSize, params.componentCount, request.ContributorCoin.Value)
	if err != nil || !equalInts(want, request.SelectedIndices) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation selection")
	}
	selectionDigest, err := cvSelectionDigestV2(
		&request.ContributorCoin, request.SelectedIndices, params.poolSize, params.componentCount,
	)
	if err != nil || !bytes.Equal(selectionDigest, request.Header.SelectionDigest) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation selection digest")
	}
	if !bytes.Equal(request.ARC.InstanceDigest, request.Header.APDBInstance) ||
		!bytes.Equal(request.ARC.Root, request.Header.APDBRoot) {
		return nil, canonicalLatency, fmt.Errorf("invalid CV V2 validation ARC binding")
	}
	if err := cvVerifyAPDBLockV2(&request.ARC, apdbSigner); err != nil {
		return nil, canonicalLatency, err
	}
	return canonical, canonicalLatency, nil
}

func cvValidationSignatureV2CanonicalBytes(value *cvValidationSignatureV2) ([]byte, error) {
	if value == nil || len(value.Statement) != 32 || len(value.Signature) == 0 || len(value.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 validation signature")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationShareWireV2Domain))
	_ = cvWriteBytes(&wire, value.Statement)
	_ = cvWriteBytes(&wire, value.Signature)
	return wire.Bytes(), nil
}

func cvDecodeValidationSignatureV2(wire []byte) (*cvValidationSignatureV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationShareWireV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationShareWireV2Domain)) {
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
	value := &cvValidationSignatureV2{Statement: statement, Signature: signature}
	canonical, err := cvValidationSignatureV2CanonicalBytes(value)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation signature")
	}
	return value, nil
}

func cvValidationResultV2CanonicalBytes(result *cvValidationResultV2, validatorSample []int) ([]byte, error) {
	if result == nil || len(result.Statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 validation result")
	}
	certificate, err := cvValidationCertificateV2CanonicalBytes(&result.Certificate, validatorSample)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvValidationResultWireV2Domain))
	_ = cvWriteBytes(&wire, result.Statement)
	_ = cvWriteBytes(&wire, certificate)
	return wire.Bytes(), nil
}

func cvDecodeValidationResultV2(wire []byte, validatorSample []int) (*cvValidationResultV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvValidationResultWireV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvValidationResultWireV2Domain)) {
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
	certificate, err := cvDecodeValidationCertificateV2(certificateWire, validatorSample)
	if err != nil {
		return nil, err
	}
	result := &cvValidationResultV2{Statement: statement, Certificate: *certificate}
	canonical, err := cvValidationResultV2CanonicalBytes(result, validatorSample)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 validation result")
	}
	return result, nil
}
