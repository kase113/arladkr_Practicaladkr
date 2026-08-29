package core

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

const cvAgreementMVBAInstanceScalar = "cv-v2-scalar-group-agreement"

func cvRunAgreementScalar(
	ctx context.Context, cfg Config, candidate *cvAgreementObjectScalar, public cvAgreementPublicContextScalar,
) (*cvAgreementObjectScalar, []byte, time.Duration, error) {
	if ctx == nil || candidate == nil {
		return nil, nil, 0, fmt.Errorf("invalid CV V2 agreement input")
	}
	_, validatorSample, err := cvAgreementEligibilitySamplesScalar(public)
	if err != nil {
		return nil, nil, 0, err
	}
	predicate := cvAggregatePredicateScalar(public)
	wire, err := cvAgreementObjectScalarWireBytes(candidate, public.Params, validatorSample)
	if err != nil || !predicate(candidate.Header.ProposerID, wire) {
		return nil, nil, 0, fmt.Errorf("invalid local CV V2 agreement candidate")
	}
	decidedWire, peerWait, err := runArladkrMVBADirectTCPInstance(
		ctx, cfg, cvAgreementMVBAInstanceScalar, wire, predicate,
		public.ControlSigner, public.CoinSigner,
	)
	if err != nil {
		return nil, nil, peerWait, err
	}
	if len(decidedWire) == 0 {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned no valid object")
	}
	if !predicate(-1, decidedWire) {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned an invalid object")
	}
	decided, err := cvDecodeAgreementObjectScalar(decidedWire, public.Params, validatorSample)
	if err != nil {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned an invalid object")
	}
	canonical, err := cvAgreementObjectScalarWireBytes(decided, public.Params, validatorSample)
	if err != nil || !bytes.Equal(canonical, decidedWire) {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned a non-canonical object")
	}
	return decided, canonical, peerWait, nil
}
