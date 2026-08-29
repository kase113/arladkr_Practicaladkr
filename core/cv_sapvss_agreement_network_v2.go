package core

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

const cvAgreementMVBAInstanceV2 = "cv-v2-scalar-group-agreement"

func cvRunAgreementV2(
	ctx context.Context, cfg Config, candidate *cvAgreementObjectV2, public cvAgreementPublicContextV2,
) (*cvAgreementObjectV2, []byte, time.Duration, error) {
	if ctx == nil || candidate == nil {
		return nil, nil, 0, fmt.Errorf("invalid CV V2 agreement input")
	}
	_, validatorSample, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		return nil, nil, 0, err
	}
	predicate := cvAggregatePredicateV2(public)
	wire, err := cvAgreementObjectV2WireBytes(candidate, public.Params, validatorSample)
	if err != nil || !predicate(candidate.Header.ProposerID, wire) {
		return nil, nil, 0, fmt.Errorf("invalid local CV V2 agreement candidate")
	}
	decidedWire, peerWait, err := runArladkrMVBADirectTCPInstance(
		ctx, cfg, cvAgreementMVBAInstanceV2, wire, predicate,
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
	decided, err := cvDecodeAgreementObjectV2(decidedWire, public.Params, validatorSample)
	if err != nil {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned an invalid object")
	}
	canonical, err := cvAgreementObjectV2WireBytes(decided, public.Params, validatorSample)
	if err != nil || !bytes.Equal(canonical, decidedWire) {
		return nil, nil, peerWait, fmt.Errorf("CV V2 agreement returned a non-canonical object")
	}
	return decided, canonical, peerWait, nil
}
