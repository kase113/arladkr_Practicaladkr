package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVReferenceEpochV2EndToEnd(t *testing.T) {
	first, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(
			t, context.OldRoster[i], context, receivers, validators,
		))
	}

	publicDir := filepath.Join(t.TempDir(), "old-threshold-public")
	secretDir := filepath.Join(t.TempDir(), "old-threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(
		publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params,
	); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(
		publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params,
	)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}

	result, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: context, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Components) != params.poolSize || len(result.SelectedIndices) != params.componentCount ||
		len(result.ShareOutputs) != len(context.NewRoster) ||
		len(result.localScalarShares) != len(context.NewRoster) || result.PublicKey.IsInfinity() {
		t.Fatal("reference V2 epoch returned incomplete artifacts")
	}
	for i, receiverID := range context.NewRoster {
		encoded := result.localScalarShares[receiverID]
		if len(encoded) != fr.Bytes {
			t.Fatalf("receiver %d scalar length = %d, want %d", receiverID, len(encoded), fr.Bytes)
		}
		var scalar fr.Element
		if err := scalar.SetBytesCanonical(encoded); err != nil {
			t.Fatalf("receiver %d stored non-canonical scalar: %v", receiverID, err)
		}
		if publicShare := cvPointTimes(&genG1, &scalar); !publicShare.Equal(&result.ShareOutputs[i].Y) {
			t.Fatalf("receiver %d stored scalar does not match public output", receiverID)
		}
	}
	if !bytes.Equal(result.Aggregate.Digest, result.RecoveredAggregate.Digest) {
		t.Fatal("reference V2 aggregate recovery changed the aggregate digest")
	}
	if err := cvVerifyHandoffV2(
		&result.Handoff, result.Header.ContextDigest, apdbSigner, controlSigner,
	); err != nil {
		t.Fatal(err)
	}
	alternate, err := cvRecoverThresholdPublicKeyV2(
		result.ShareOutputs[1:], result.RecoveredAggregate, context, params, receivers,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !alternate.Equal(&result.PublicKey) {
		t.Fatal("reference V2 threshold share subsets produced different public keys")
	}
	metrics, err := cvReferenceMetricsV2(result, context)
	if err != nil {
		t.Fatal(err)
	}
	_, _, chunks, err := cvProfile(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	const ciphertextBytes = 2 * bls12381.SizeOfG1AffineCompressed
	wantScalarBytes := params.poolSize * len(context.NewRoster) * chunks * ciphertextBytes
	wantBlindingBytes := params.poolSize * len(context.NewRoster) * ciphertextBytes
	if metrics.ComponentScalarCiphertextBytes != wantScalarBytes ||
		metrics.ComponentBlindingCiphertextBytes != wantBlindingBytes ||
		metrics.AggregatePayloadBytes != len(result.AggregatePayload) ||
		metrics.FallbackLinkProofBytes != 0 || metrics.FallbackRangeProofBytes != 0 {
		t.Fatalf("unexpected V2 scalar/group metrics: %+v", metrics)
	}
	if metrics.ScalarBoundedDLogMilliseconds <= 0 || metrics.BlindingGroupDecryptMilliseconds <= 0 {
		t.Fatalf("missing V2 scalar/group decryption timings: %+v", metrics)
	}
	handoffDigest, err := cvHandoffDigestV2(result.Handoff.ContextDigest, &result.Handoff.Header, &result.Handoff.ARC)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes := result.PublicKey.Bytes()
	jsonWire, err := json.Marshal(&CVV2ReferenceExperimentResult{
		Protocol: cvSAPVSSV2ReferenceExperimentProtocol, SID: context.SID, Epoch: context.Epoch,
		SelectedIndices: append([]int(nil), result.SelectedIndices...),
		AggregateDigest: hex.EncodeToString(result.Aggregate.Digest),
		HandoffDigest:   hex.EncodeToString(handoffDigest),
		PublicKey:       hex.EncodeToString(publicKeyBytes[:]),
		Metrics:         metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicWires := [][]byte{result.AgreementWire, result.HandoffWire, result.AggregatePayload}
	for _, output := range result.ShareOutputs {
		wire, encodeErr := cvScalarShareOutputV2CanonicalBytes(output)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		publicWires = append(publicWires, wire)
	}
	for receiverID, scalar := range result.localScalarShares {
		for _, wire := range publicWires {
			if bytes.Contains(wire, scalar) {
				t.Fatalf("receiver %d scalar leaked into a public protocol wire", receiverID)
			}
		}
		if bytes.Contains(jsonWire, []byte(hex.EncodeToString(scalar))) {
			t.Fatalf("receiver %d scalar leaked into reference JSON", receiverID)
		}
	}
	if result.Timings.Total <= 0 || result.Timings.Components <= 0 || result.Timings.Shares <= 0 {
		t.Fatal("reference V2 epoch did not record experiment phase timings")
	}
	t.Logf("reference V2 timings: components=%s pool=%s aggregate=%s validation=%s agreement=%s handoff=%s recovery=%s shares=%s total=%s",
		result.Timings.Components, result.Timings.Pool, result.Timings.Aggregate,
		result.Timings.Validation, result.Timings.Agreement, result.Timings.Handoff,
		result.Timings.Recovery, result.Timings.Shares, result.Timings.Total)
}
