package core

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvHintsDecodeBaseline(t *testing.T, wire []byte, context *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) []byte {
	t.Helper()
	leaf, err := cvDecodeLeafV2(wire, context, receivers, validators)
	if err != nil {
		t.Fatalf("baseline decode failed: %v", err)
	}
	return leaf.Digest
}

func TestCVPayloadHintsRoundTripEquivalence(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := cvHintsDecodeBaseline(t, wire, context, receivers, validators)

	hints := cvRecordLeafDeferredHintsV2(wire, context, receivers, validators)
	if len(hints) == 0 {
		t.Fatal("recording produced no hints for a valid leaf")
	}
	if len(hints)%bls12381.SizeOfG1AffineUncompressed != 0 {
		t.Fatalf("hint stream not a multiple of the uncompressed point size: %d", len(hints))
	}
	decoded, err := cvDecodeLeafV2WithHints(wire, hints, context, receivers, validators)
	if err != nil {
		t.Fatalf("hint decode failed: %v", err)
	}
	if !bytes.Equal(decoded.Digest, wantDigest) {
		t.Fatal("hint decode produced a different leaf digest")
	}
	if err := cvVerifyAPVSSV2(decoded, context, receivers, validators); err != nil {
		t.Fatalf("hint-decoded leaf did not verify: %v", err)
	}
}

func TestCVDealerPayloadResponseCanOmitHints(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	payload, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	newService := func() *cvAPDBNetworkServiceV2 {
		return &cvAPDBNetworkServiceV2{cfg: cvAPDBNetworkServiceConfigV2{
			MaximumPayload: len(payload), LeafContext: context, Receivers: receivers, Validators: validators,
		}}
	}
	instance := bytes.Repeat([]byte{9}, 32)

	t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", "1")
	withHints, err := cvDecodeAPDBPayloadResponseV2(newService().dealerPayloadResponseV2(instance, payload), len(payload))
	if err != nil || len(withHints.Hints) == 0 {
		t.Fatalf("enabled dealer hints bytes=%d err=%v", len(withHints.Hints), err)
	}

	t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", "0")
	withoutHints, err := cvDecodeAPDBPayloadResponseV2(newService().dealerPayloadResponseV2(instance, payload), len(payload))
	if err != nil || len(withoutHints.Hints) != 0 || !bytes.Equal(withoutHints.Payload, payload) {
		t.Fatalf("payload-only response hints=%d err=%v", len(withoutHints.Hints), err)
	}
}

func TestCVPayloadHintsDefaultToPayloadOnly(t *testing.T) {
	t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", "")
	if CVPayloadHintsEnabled() {
		t.Fatal("payload hints enabled by default, want payload-only")
	}
	for _, value := range []string{"1", "true", "ON", "enabled"} {
		t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", value)
		if !CVPayloadHintsEnabled() {
			t.Fatalf("payload hints disabled for explicit value %q", value)
		}
	}
	for _, value := range []string{"0", "false", "off", "invalid"} {
		t.Setenv("RLADKR_APDB_PAYLOAD_HINTS", value)
		if CVPayloadHintsEnabled() {
			t.Fatalf("payload hints enabled for value %q", value)
		}
	}
}

func TestCVPayloadHintsCorruptionFallsBack(t *testing.T) {
	leaf, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := cvHintsDecodeBaseline(t, wire, context, receivers, validators)
	hints := cvRecordLeafDeferredHintsV2(wire, context, receivers, validators)
	entry := bls12381.SizeOfG1AffineUncompressed
	mid := (len(hints) / entry / 2) * entry

	corruptions := map[string][]byte{
		"flipped middle byte": func() []byte {
			flipped := append([]byte(nil), hints...)
			flipped[mid] ^= 0xff
			return flipped
		}(),
		"truncated last entry": append([]byte(nil), hints[:len(hints)-entry]...),
		"extra garbage entry":  append(append([]byte(nil), hints...), make([]byte, entry)...),
		"swapped entries": func() []byte {
			swapped := append([]byte(nil), hints...)
			if len(swapped) >= 2*entry {
				copy(swapped[0:entry], hints[entry:2*entry])
				copy(swapped[entry:2*entry], hints[0:entry])
			}
			return swapped
		}(),
		"empty stream":     nil,
		"wrong-sized tail": append(append([]byte(nil), hints...), 1),
	}
	for name, corrupted := range corruptions {
		decoded, err := cvDecodeLeafV2WithHints(wire, corrupted, context, receivers, validators)
		if err != nil {
			t.Fatalf("%s: decode failed after hint corruption: %v", name, err)
		}
		if !bytes.Equal(decoded.Digest, wantDigest) {
			t.Fatalf("%s: corrupted hints changed the decoded leaf", name)
		}
	}
}

// TestCVRecompressMatchesGnarkCompression pins the binding primitive to
// gnark's own serialization: whatever gnark compresses, recompression must
// reproduce byte-for-byte, and the negation must not.
func TestCVRecompressMatchesGnarkCompression(t *testing.T) {
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	points := []bls12381.G1Affine{genG1, h}
	var scalar fr.Element
	for i := 0; i < 8; i++ {
		if _, err := scalar.SetRandom(); err != nil {
			t.Fatal(err)
		}
		var random bls12381.G1Affine
		random.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
		points = append(points, random)
	}
	for i := range points {
		encoded := points[i].Bytes()
		if !cvRecompressG1Equals(&points[i], encoded[:]) {
			t.Fatalf("recompression diverged from gnark for point %d", i)
		}
		var negated bls12381.G1Affine
		negated.Neg(&points[i])
		if cvRecompressG1Equals(&negated, encoded[:]) {
			t.Fatalf("recompression matched the negated point %d", i)
		}
		var infinity bls12381.G1Affine
		encodedInfinity := infinity.Bytes()
		if !cvRecompressG1Equals(&infinity, encodedInfinity[:]) {
			t.Fatal("recompression diverged from gnark for infinity")
		}
	}
}

// TestCVPayloadHintsRejectOffCurveInjection covers the security-critical
// case: a hint whose x and y-parity recompress to the exact wire bytes but
// whose y-coordinate is not on the curve. The on-curve check must reject it,
// so the decode falls back to the square-root path and still returns the
// signed point.
func TestCVPayloadHintsRejectOffCurveInjection(t *testing.T) {
	var wirePoint bls12381.G1Affine
	var scalar fr.Element
	if _, err := scalar.SetRandom(); err != nil {
		t.Fatal(err)
	}
	wirePoint.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
	encoded := wirePoint.Bytes()

	parityOK := wirePoint.Y.LexicographicallyLargest()
	var offCurve fp.Element
	found := false
	for k := uint64(2); k < 40 && !found; k++ {
		offCurve.SetUint64(k).Mul(&offCurve, &wirePoint.Y)
		if offCurve.Equal(&wirePoint.Y) {
			continue
		}
		var negated fp.Element
		negated.Neg(&wirePoint.Y)
		if offCurve.Equal(&negated) {
			continue
		}
		if offCurve.LexicographicallyLargest() == parityOK {
			found = true
			break
		}
	}
	if !found {
		t.Skip("no parity-preserving off-curve multiple sampled")
	}

	hint := cvAppendG1HintUncompressed(nil, &bls12381.G1Affine{X: wirePoint.X, Y: offCurve})
	if _, err := cvDecodeG1HintUnchecked(hint); err == nil {
		t.Fatal("off-curve hint passed the on-curve check")
	}
	side := newCVDecodeSidechannelHintsV2(hint)
	if _, ok := side.consumeHint(encoded[:]); ok {
		t.Fatal("off-curve hint with matching parity was consumed")
	}
	if side.usable {
		t.Fatal("sidechannel stayed usable after a rejected hint")
	}

	// After the rejection the reader must fall back and decode the signed
	// point exactly as the legacy path would.
	r := newCVWireReaderSide(encoded[:], side)
	point, err := r.pointDeferred()
	if err != nil {
		t.Fatalf("fallback decode failed: %v", err)
	}
	if !point.Equal(&wirePoint) {
		t.Fatal("fallback decode did not reproduce the signed point")
	}
}

// TestCVPayloadHintsSubgroupSafetyUnchanged proves a hint that faithfully
// mirrors a non-subgroup wire point is still rejected: hints change only how
// y is obtained, and the deferred batch subgroup check still runs.
func TestCVPayloadHintsSubgroupSafetyUnchanged(t *testing.T) {
	outsider := cvRandomCurvePointOutsideSubgroup(t)
	first := genG1.Bytes()
	second := outsider.Bytes()
	wire := append(append([]byte(nil), first[:]...), second[:]...)

	hints := cvAppendG1HintUncompressed(nil, &genG1)
	hints = cvAppendG1HintUncompressed(hints, &outsider)
	side := newCVDecodeSidechannelHintsV2(hints)
	r := newCVWireReaderSide(wire, side)
	if _, err := r.pointDeferred(); err != nil {
		t.Fatal(err)
	}
	outsiderDecoded, err := r.pointDeferred()
	if err != nil {
		t.Fatal(err)
	}
	if !outsiderDecoded.Equal(&outsider) {
		t.Fatal("hint decode did not reproduce the non-subgroup fixture point")
	}
	if len(r.deferredPoints) != 2 || len(side.hints) != 0 {
		t.Fatal("hint stream or deferred batch did not advance as expected")
	}
	if err := r.assertDecodedSubgroup(); err == nil {
		t.Fatal("batch subgroup check accepted a hint-supplied non-subgroup point")
	}
}

func TestCVAPDBPayloadResponseHintsWireRoundTrip(t *testing.T) {
	instanceDigest := bytes.Repeat([]byte{7}, 32)
	payload := []byte("component payload")
	hints := cvAppendG1HintUncompressed(nil, &genG1)

	withHints, err := cvAPDBPayloadResponseV2CanonicalBytes(
		&cvAPDBPayloadResponseV2{InstanceDigest: instanceDigest, Payload: payload, Hints: hints},
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAPDBPayloadResponseV2(withHints, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Hints, hints) {
		t.Fatal("hints did not survive the response wire round trip")
	}

	legacy, err := cvAPDBPayloadResponseV2CanonicalBytes(
		&cvAPDBPayloadResponseV2{InstanceDigest: instanceDigest, Payload: payload},
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legacy, withHints) {
		t.Fatal("legacy response should not carry hint bytes")
	}
	decodedLegacy, err := cvDecodeAPDBPayloadResponseV2(legacy, 1024)
	if err != nil || len(decodedLegacy.Hints) != 0 {
		t.Fatal("legacy response decode changed behavior")
	}

	oversized := append([]byte(nil), hints...)
	for len(oversized) <= cvMaxPayloadHintsBytesV2(8) {
		oversized = append(oversized, hints...)
	}
	overWire, err := cvAPDBPayloadResponseV2CanonicalBytes(
		&cvAPDBPayloadResponseV2{InstanceDigest: instanceDigest, Payload: payload, Hints: oversized},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeAPDBPayloadResponseV2(overWire, 8); err == nil {
		t.Fatal("oversized hint attachment was accepted")
	}
	trailing := append(append([]byte(nil), withHints...), 0)
	if _, err := cvDecodeAPDBPayloadResponseV2(trailing, 1024); err == nil {
		t.Fatal("trailing bytes after the hint field were accepted")
	}
	misaligned := cvAppendG1HintUncompressed(nil, &genG1)[:95]
	if _, err := cvAPDBPayloadResponseV2CanonicalBytes(
		&cvAPDBPayloadResponseV2{InstanceDigest: instanceDigest, Payload: payload, Hints: misaligned},
	); err == nil {
		t.Fatal("misaligned hint attachment was encoded")
	}
}
