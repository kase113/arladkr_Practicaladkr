package core

import "testing"

func TestCVAgreementSizeReportScalarExactDecomposition(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	_, validatorSample, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	report, err := cvAgreementSizeReportScalar(object, public.Params, validatorSample)
	if err != nil {
		t.Fatal(err)
	}
	assertCVAgreementSizeDecompositionScalar(t, report)
}

func TestCVAgreementSizeReportScalarValidatorBitmapBoundaries(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	var previous CVScalarAgreementSizeReport
	for _, sampleSize := range []int{1, 7, 8, 9} {
		sample := make([]int, sampleSize)
		for i := range sample {
			sample[i] = i
		}
		candidate := *object
		candidate.VCert = object.VCert
		candidate.VCert.SignerBitmap = make([]byte, cvValidationBitmapBytesScalar(sampleSize))
		report, err := cvAgreementSizeReportScalar(&candidate, public.Params, sample)
		if err != nil {
			t.Fatalf("sample size %d: %v", sampleSize, err)
		}
		assertCVAgreementSizeDecompositionScalar(t, report)
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

func TestCVAgreementSizeReportScalarPoolComponentScaling(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	_, validatorSample, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	var previous CVScalarAgreementSizeReport
	for poolSize := 1; poolSize <= len(object.Pool.Components); poolSize++ {
		params := public.Params
		params.poolSize = poolSize
		params.componentCount = 1
		pool, err := cvBuildPoolScalar(
			object.Pool.ContextDigest, object.Pool.ProposerID, object.Pool.Components[:poolSize], params,
		)
		if err != nil {
			t.Fatalf("pool size %d: %v", poolSize, err)
		}
		candidate := *object
		candidate.Pool = *pool
		candidate.SelectedIndices = []int{0}
		report, err := cvAgreementSizeReportScalar(&candidate, params, validatorSample)
		if err != nil {
			t.Fatalf("pool size %d: %v", poolSize, err)
		}
		assertCVAgreementSizeDecompositionScalar(t, report)
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

func assertCVAgreementSizeDecompositionScalar(t *testing.T, report CVScalarAgreementSizeReport) {
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
