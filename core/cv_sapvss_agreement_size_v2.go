package core

import (
	"bytes"
	"fmt"
)

type CVV2AgreementSizeReport struct {
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

func cvAgreementSizeReportV2(
	object *cvAgreementObjectV2, params cvV2Params, validatorSample []int,
) (CVV2AgreementSizeReport, error) {
	agreementWire, err := cvAgreementObjectV2CanonicalBytes(object, params, validatorSample)
	if err != nil {
		return CVV2AgreementSizeReport{}, err
	}
	poolWire, err := cvPoolV2CanonicalBytes(&object.Pool, params)
	if err != nil {
		return CVV2AgreementSizeReport{}, err
	}
	componentReferenceBytes := 0
	componentBytes := 0
	for i, component := range object.Pool.Components {
		wire, encodeErr := cvComponentRefV2CanonicalBytes(component)
		if encodeErr != nil {
			return CVV2AgreementSizeReport{}, encodeErr
		}
		var framed bytes.Buffer
		if encodeErr := cvWriteBytes(&framed, wire); encodeErr != nil {
			return CVV2AgreementSizeReport{}, encodeErr
		}
		if i == 0 {
			componentReferenceBytes = framed.Len()
		} else if framed.Len() != componentReferenceBytes {
			return CVV2AgreementSizeReport{}, fmt.Errorf("CV V2 component reference wire size is not constant")
		}
		componentBytes += framed.Len()
	}
	vCertWire, err := cvValidationCertificateV2CanonicalBytes(&object.VCert, validatorSample)
	if err != nil {
		return CVV2AgreementSizeReport{}, err
	}
	bitmapBytes := cvValidationBitmapBytesV2(len(validatorSample))
	selectedBytes := 8 * len(object.SelectedIndices)
	poolFixed := len(poolWire) - componentBytes
	vCertFixed := len(vCertWire) - bitmapBytes
	agreementFixed := len(agreementWire) - len(poolWire) - selectedBytes - len(vCertWire)
	if componentReferenceBytes <= 0 || poolFixed <= 0 || vCertFixed <= 0 || agreementFixed <= 0 ||
		len(poolWire) != poolFixed+len(object.Pool.Components)*componentReferenceBytes ||
		len(vCertWire) != vCertFixed+bitmapBytes ||
		len(agreementWire) != agreementFixed+len(poolWire)+selectedBytes+len(vCertWire) {
		return CVV2AgreementSizeReport{}, fmt.Errorf("invalid CV V2 agreement size decomposition")
	}
	return CVV2AgreementSizeReport{
		AgreementBytes: len(agreementWire), AgreementFixedBytes: agreementFixed,
		CompactAgreementBytes: func() int {
			wire, err := cvAgreementObjectV2CompactCanonicalBytes(object, params, validatorSample)
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
