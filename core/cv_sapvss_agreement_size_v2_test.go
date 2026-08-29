package core

import "testing"

func TestCVV2ReferenceAndNetworkProtocolLabelsDiffer(t *testing.T) {
	if cvSAPVSSV2ReferenceExperimentProtocol == cvSAPVSSV2ProtocolVersion {
		t.Fatal("reference and network V2 results share one protocol label")
	}
}

func TestCVAgreementSizeReportV2ExactDecomposition(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, validatorSample, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	report, err := cvAgreementSizeReportV2(object, public.Params, validatorSample)
	if err != nil {
		t.Fatal(err)
	}
	assertCVAgreementSizeDecompositionV2(t, report)
}

func TestCVAgreementSizeReportV2ValidatorBitmapBoundaries(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	var previous CVV2AgreementSizeReport
	for _, sampleSize := range []int{1, 7, 8, 9} {
		sample := make([]int, sampleSize)
		for i := range sample {
			sample[i] = i
		}
		candidate := *object
		candidate.VCert = object.VCert
		candidate.VCert.SignerBitmap = make([]byte, cvValidationBitmapBytesV2(sampleSize))
		report, err := cvAgreementSizeReportV2(&candidate, public.Params, sample)
		if err != nil {
			t.Fatalf("sample size %d: %v", sampleSize, err)
		}
		assertCVAgreementSizeDecompositionV2(t, report)
		if report.ValidatorBitmapBytes != (sampleSize+7)/8 {
			t.Fatalf("sample size %d: bitmap bytes = %d", sampleSize, report.ValidatorBitmapBytes)
		}
		if sampleSize == 7 || sampleSize == 8 {
			if report.ValidationCertificateBytes != previous.ValidationCertificateBytes ||
				report.AgreementBytes != previous.AgreementBytes {
				t.Fatalf("sample size %d changed wire size within one bitmap byte", sampleSize)
			}
		}
		if sampleSize == 9 {
			if report.ValidationCertificateBytes != previous.ValidationCertificateBytes+1 ||
				report.AgreementBytes != previous.AgreementBytes+1 {
				t.Fatal("ninth validator did not add exactly one bitmap byte")
			}
		}
		previous = report
	}
}

func TestCVAgreementSizeReportV2PoolComponentScaling(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, validatorSample, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	var previous CVV2AgreementSizeReport
	for poolSize := 1; poolSize <= len(object.Pool.Components); poolSize++ {
		params := public.Params
		params.poolSize = poolSize
		params.componentCount = 1
		pool, err := cvBuildPoolV2(
			object.Pool.ContextDigest, object.Pool.ProposerID, object.Pool.Components[:poolSize], params,
		)
		if err != nil {
			t.Fatalf("pool size %d: %v", poolSize, err)
		}
		candidate := *object
		candidate.Pool = *pool
		candidate.SelectedIndices = []int{0}
		report, err := cvAgreementSizeReportV2(&candidate, params, validatorSample)
		if err != nil {
			t.Fatalf("pool size %d: %v", poolSize, err)
		}
		assertCVAgreementSizeDecompositionV2(t, report)
		if poolSize > 1 {
			if report.PoolBytes != previous.PoolBytes+report.ComponentReferenceBytes ||
				report.AgreementBytes != previous.AgreementBytes+report.ComponentReferenceBytes {
				t.Fatalf("pool size %d did not add exactly one framed component reference", poolSize)
			}
			if report.PoolFixedBytes != previous.PoolFixedBytes ||
				report.AgreementFixedBytes != previous.AgreementFixedBytes {
				t.Fatalf("pool size %d changed a fixed-size term", poolSize)
			}
		}
		previous = report
	}
}

func assertCVAgreementSizeDecompositionV2(t *testing.T, report CVV2AgreementSizeReport) {
	t.Helper()
	if report.PoolBytes != report.PoolFixedBytes+report.PoolComponentCount*report.ComponentReferenceBytes {
		t.Fatal("Pool wire size does not match fixed + L*component")
	}
	if report.ValidationCertificateBytes != report.ValidationCertificateFixedBytes+report.ValidatorBitmapBytes {
		t.Fatal("VCert wire size does not match fixed + ceil(c_val/8)")
	}
	if report.SelectedIndexBytes != 8*report.SelectedIndexCount {
		t.Fatal("selected-index wire size does not match 8*K")
	}
	if report.AgreementBytes != report.AgreementFixedBytes+report.PoolBytes+
		report.SelectedIndexBytes+report.ValidationCertificateBytes {
		t.Fatal("agreement wire size does not match its exact decomposition")
	}
}
