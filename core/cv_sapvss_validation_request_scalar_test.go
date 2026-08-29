package core

import (
	"bytes"
	"testing"
)

func TestCVValidationRequestScalarCodecAndPublicChecks(t *testing.T) {
	object, public := cvAgreementObjectScalarFixture(t)
	request := &cvValidationRequestScalar{
		Header: object.Header, Pool: object.Pool, PoolCert: object.PoolCert,
		ContributorCoin: object.ContributorCoin, SelectedIndices: append([]int(nil), object.SelectedIndices...), ARC: object.ARC,
	}
	proposers, validators, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyValidationRequestPublicScalar(request, public.ContextDigest, public.Params, nodeSet(proposers),
		public.APDBSigner, public.ControlSigner, public.CoinSigner); err != nil {
		t.Fatal(err)
	}
	wire, err := cvValidationRequestScalarCanonicalBytes(request, public.Params)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeValidationRequestScalar(wire, public.Params)
	if err != nil || !bytes.Equal(decoded.Header.AggregateDigest, request.Header.AggregateDigest) {
		t.Fatalf("round-trip CV V2 validation request: %v", err)
	}
	if _, err := cvDecodeValidationRequestScalar(append(append([]byte(nil), wire...), 0), public.Params); err == nil {
		t.Fatal("accepted trailing CV V2 validation request bytes")
	}

	statement, err := cvValidationStatementScalar(validators, &request.Header)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := cvSignValidationScalar(validators[0], &request.Header, validators, public.ValidatorKeys)
	if err != nil {
		t.Fatal(err)
	}
	shareWire, err := cvValidationSignatureScalarCanonicalBytes(&cvValidationSignatureScalar{Statement: statement, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeValidationSignatureScalar(shareWire); err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeValidationSignatureScalar(append(append([]byte(nil), shareWire...), 0)); err == nil {
		t.Fatal("accepted trailing CV V2 validation signature bytes")
	}

	mutated := *request
	mutated.SelectedIndices = append([]int(nil), request.SelectedIndices...)
	mutated.SelectedIndices[0] = (mutated.SelectedIndices[0] + 1) % public.Params.poolSize
	if err := cvVerifyValidationRequestPublicScalar(&mutated, public.ContextDigest, public.Params, nodeSet(proposers),
		public.APDBSigner, public.ControlSigner, public.CoinSigner); err == nil {
		t.Fatal("accepted mutated CV V2 validation selection")
	}
}
