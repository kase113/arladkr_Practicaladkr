package core

import (
	"bytes"
	"testing"
)

func TestCVValidationRequestV2CodecAndPublicChecks(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	request := &cvValidationRequestV2{
		Header: object.Header, Pool: object.Pool, PoolCert: object.PoolCert,
		ContributorCoin: object.ContributorCoin, SelectedIndices: append([]int(nil), object.SelectedIndices...), ARC: object.ARC,
	}
	proposers, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyValidationRequestPublicV2(request, public.ContextDigest, public.Params, nodeSet(proposers),
		public.APDBSigner, public.ControlSigner, public.CoinSigner); err != nil {
		t.Fatal(err)
	}
	wire, err := cvValidationRequestV2CanonicalBytes(request, public.Params)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeValidationRequestV2(wire, public.Params)
	if err != nil || !bytes.Equal(decoded.Header.AggregateDigest, request.Header.AggregateDigest) {
		t.Fatalf("round-trip CV V2 validation request: %v", err)
	}
	if _, err := cvDecodeValidationRequestV2(append(append([]byte(nil), wire...), 0), public.Params); err == nil {
		t.Fatal("accepted trailing CV V2 validation request bytes")
	}

	statement, err := cvValidationStatementV2(validators, &request.Header)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := cvSignValidationV2(validators[0], &request.Header, validators, public.ValidatorKeys)
	if err != nil {
		t.Fatal(err)
	}
	shareWire, err := cvValidationSignatureV2CanonicalBytes(&cvValidationSignatureV2{Statement: statement, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeValidationSignatureV2(shareWire); err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeValidationSignatureV2(append(append([]byte(nil), shareWire...), 0)); err == nil {
		t.Fatal("accepted trailing CV V2 validation signature bytes")
	}

	mutated := *request
	mutated.SelectedIndices = append([]int(nil), request.SelectedIndices...)
	mutated.SelectedIndices[0] = (mutated.SelectedIndices[0] + 1) % public.Params.poolSize
	if err := cvVerifyValidationRequestPublicV2(&mutated, public.ContextDigest, public.Params, nodeSet(proposers),
		public.APDBSigner, public.ControlSigner, public.CoinSigner); err == nil {
		t.Fatal("accepted mutated CV V2 validation selection")
	}
}
