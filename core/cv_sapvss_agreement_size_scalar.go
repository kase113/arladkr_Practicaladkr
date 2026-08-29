package core

import (
	"bytes"
	"fmt"
)

type CVScalarAgreementSizeReport struct {
	AgreementBytes                  int `json:"agreement_bytes"`
	CompactAgreementBytes           int `json:"compact_agreement_bytes,omitempty"`
	AgreementFixedBytes             int `json:"agreement_fixed_bytes"`
	PoolBytes                       int `json:"pool_bytes"`
	PoolFixedBytes                  int `json:"pool_fixed_bytes"`
	PoolComponentCount              int `json:"pool_component_count"`
	ComponentReferenceBytes         int `json:"component_reference_bytes"`
	SelectedIndexCount              int `json:"selected_index_count"`
	SelectedIndexBytes              int `json:"selected_index_bytes"`
	ValidatorSampleSize             int `json:"validator_sample_size"`
	ValidatorBitmapBytes            int `json:"validator_bitmap_bytes"`
	ValidationCertificateBytes      int `json:"validation_certificate_bytes"`
	ValidationCertificateFixedBytes int `json:"validation_certificate_fixed_bytes"`
}

func cvAgreementSizeReportScalar(
	object *cvAgreementObjectScalar, params cvScalarParams, validatorSample []int,
) (CVScalarAgreementSizeReport, error) {
	agreementWire, err := cvAgreementObjectScalarCanonicalBytes(object, params, validatorSample)
	if err != nil {
		return CVScalarAgreementSizeReport{}, err
	}
	poolWire, err := cvPoolScalarCanonicalBytes(&object.Pool, params)
	if err != nil {
		return CVScalarAgreementSizeReport{}, err
	}
	componentReferenceBytes := 0
	componentBytes := 0
	for i, component := range object.Pool.Components {
		wire, encodeErr := cvComponentRefScalarCanonicalBytes(component)
		if encodeErr != nil {
			return CVScalarAgreementSizeReport{}, encodeErr
		}
		var framed bytes.Buffer
		if encodeErr := cvWriteBytes(&framed, wire); encodeErr != nil {
			return CVScalarAgreementSizeReport{}, encodeErr
		}
		if i == 0 {
			componentReferenceBytes = framed.Len()
		} else if framed.Len() != componentReferenceBytes {
			return CVScalarAgreementSizeReport{}, fmt.Errorf("CV V2 component reference wire size is not constant")
		}
		componentBytes += framed.Len()
	}
	vCertWire, err := cvValidationCertificateScalarCanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return CVScalarAgreementSizeReport{}, err
	}
	bitmapBytes := cvValidationBitmapBytesScalar(len(validatorSample))
	selectedBytes := 8 * len(object.SelectedIndices)
	poolFixed := len(poolWire) - componentBytes
	vCertFixed := len(vCertWire) - bitmapBytes
	agreementFixed := len(agreementWire) - len(poolWire) - selectedBytes - len(vCertWire)
	if componentReferenceBytes <= 0 || poolFixed <= 0 || vCertFixed <= 0 || agreementFixed <= 0 ||
		len(poolWire) != poolFixed+len(object.Pool.Components)*componentReferenceBytes ||
		len(vCertWire) != vCertFixed+bitmapBytes ||
		len(agreementWire) != agreementFixed+len(poolWire)+selectedBytes+len(vCertWire) {
		return CVScalarAgreementSizeReport{}, fmt.Errorf("invalid CV V2 agreement size decomposition")
	}
	return CVScalarAgreementSizeReport{
		AgreementBytes: len(agreementWire), AgreementFixedBytes: agreementFixed,
		CompactAgreementBytes: func() int {
			wire, err := cvAgreementObjectScalarCompactCanonicalBytes(object, params, validatorSample)
			if err != nil {
				return 0
			}
			return len(wire)
		}(),
		PoolBytes: len(poolWire), PoolFixedBytes: poolFixed,
		PoolComponentCount: len(object.Pool.Components), ComponentReferenceBytes: componentReferenceBytes,
		SelectedIndexCount: len(object.SelectedIndices), SelectedIndexBytes: selectedBytes,
		ValidatorSampleSize: len(validatorSample), ValidatorBitmapBytes: bitmapBytes,
		ValidationCertificateBytes: len(vCertWire), ValidationCertificateFixedBytes: vCertFixed,
	}, nil
}
