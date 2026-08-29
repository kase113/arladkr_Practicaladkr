package core

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// Payload responses may attach uncompressed G1 hints to avoid repeated square
// roots. Each hint must recompress to the signed canonical point bytes.

// cvDecodeSidechannelScalar carries one leaf decode's hint state across the
// nested wire readers that read deferred points. A single instance is shared
// by all readers of one decode so consumption order matches the record order.
type cvDecodeSidechannelScalar struct {
	// hints holds the remaining uncompressed point encodings.
	hints []byte
	// usable turns false on the first shortage or mismatch; the decode then
	// falls back to square roots for the rest of the leaf.
	usable bool
	// record, when non-nil, appends the uncompressed form of every deferred
	// point as it is decoded, building the attachment a dealer will serve.
	record []byte
	// collectSubgroup moves each reader's deferred subgroup check into
	// deferredBatch so a full leaf pays one linear combination and one
	// order-r check instead of one pair per wire section.
	collectSubgroup bool
	deferredBatch   []bls12381.G1Affine
}

// finishDeferredSubgroupBatch runs the single leaf-level subgroup check and
// resets the collector; acceptance semantics are unchanged because the leaf is
// rejected here before any caller can use its structures.
func (side *cvDecodeSidechannelScalar) finishDeferredSubgroupBatch() error {
	if side == nil || len(side.deferredBatch) == 0 {
		return nil
	}
	points := side.deferredBatch
	side.deferredBatch = nil
	return cvAssertG1SubgroupBatch(points)
}

func newCVDecodeSidechannelHintsScalar(hints []byte) *cvDecodeSidechannelScalar {
	if len(hints) == 0 {
		return nil
	}
	return &cvDecodeSidechannelScalar{hints: hints, usable: true}
}

func newCVDecodeSidechannelRecordingScalar() *cvDecodeSidechannelScalar {
	return &cvDecodeSidechannelScalar{record: make([]byte, 0, 64*bls12381.SizeOfG1AffineUncompressed)}
}

// cvAppendG1HintUncompressed appends the gnark uncompressed encoding of point.
func cvAppendG1HintUncompressed(out []byte, point *bls12381.G1Affine) []byte {
	var hint [bls12381.SizeOfG1AffineUncompressed]byte
	if point.IsInfinity() {
		hint[0] = cvG1UncompressedInfinity
		return append(out, hint[:]...)
	}
	x := point.X.Bytes()
	y := point.Y.Bytes()
	copy(hint[:fp.Bytes], x[:])
	copy(hint[fp.Bytes:fp.Bytes*2], y[:])
	return append(out, hint[:]...)
}

// cvDecodeG1HintUnchecked parses one uncompressed hint entry. Unlike the
// square-root path, curve membership is not implied, so it is checked
// explicitly; canonical field encodings are enforced by SetBytesCanonical.
func cvDecodeG1HintUnchecked(hint []byte) (bls12381.G1Affine, error) {
	if len(hint) < bls12381.SizeOfG1AffineUncompressed {
		return bls12381.G1Affine{}, fmt.Errorf("truncated CV point hint")
	}
	masked := hint[0] & cvG1Mask
	if cvG1MaskInvalid(hint[0]) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV point hint mask")
	}
	if masked == cvG1UncompressedInfinity {
		if !cvG1BufferZeroed(hint[0]&^cvG1Mask, hint[1:bls12381.SizeOfG1AffineUncompressed]) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV point hint infinity")
		}
		return bls12381.G1Affine{}, nil
	}
	if masked != cvG1Uncompressed {
		return bls12381.G1Affine{}, fmt.Errorf("CV point hint not uncompressed")
	}
	var point bls12381.G1Affine
	if err := point.X.SetBytesCanonical(hint[:fp.Bytes]); err != nil {
		return bls12381.G1Affine{}, err
	}
	if err := point.Y.SetBytesCanonical(hint[fp.Bytes : fp.Bytes*2]); err != nil {
		return bls12381.G1Affine{}, err
	}
	var lhs, rhs fp.Element
	lhs.Square(&point.Y)
	rhs.Square(&point.X).Mul(&rhs, &point.X)
	// BLS12-381 G1 curve coefficient b is 4.
	rhs.Add(&rhs, new(fp.Element).SetUint64(4))
	if !lhs.Equal(&rhs) {
		return bls12381.G1Affine{}, fmt.Errorf("CV point hint not on curve")
	}
	return point, nil
}

// cvRecompressG1Equals binds a point hint to canonical compressed bytes.
func cvRecompressG1Equals(point *bls12381.G1Affine, encoded []byte) bool {
	if len(encoded) < bls12381.SizeOfG1AffineCompressed {
		return false
	}
	var recompressed [bls12381.SizeOfG1AffineCompressed]byte
	if point.IsInfinity() {
		recompressed[0] = cvG1CompressedInfinity
	} else {
		x := point.X.Bytes()
		copy(recompressed[:fp.Bytes], x[:])
		if point.Y.LexicographicallyLargest() {
			recompressed[0] |= cvG1CompressedLargest
		} else {
			recompressed[0] |= cvG1CompressedSmallest
		}
	}
	return bytes.Equal(recompressed[:], encoded[:bls12381.SizeOfG1AffineCompressed])
}

// consumeHint returns the point for encoded, preferring the sidechannel's
// next uncompressed hint when it recompresses to the exact wire bytes.
func (side *cvDecodeSidechannelScalar) consumeHint(encoded []byte) (bls12381.G1Affine, bool) {
	if side == nil || !side.usable {
		return bls12381.G1Affine{}, false
	}
	if len(side.hints) < bls12381.SizeOfG1AffineUncompressed {
		side.usable = false
		return bls12381.G1Affine{}, false
	}
	point, err := cvDecodeG1HintUnchecked(side.hints[:bls12381.SizeOfG1AffineUncompressed])
	if err != nil || !cvRecompressG1Equals(&point, encoded) {
		side.usable = false
		return bls12381.G1Affine{}, false
	}
	side.hints = side.hints[bls12381.SizeOfG1AffineUncompressed:]
	return point, true
}

// cvPayloadHintsEnabledScalar gates both serving and consuming payload point
// hints; the wire stays compatible either way because the attachment is an
// optional trailing field.
func cvPayloadHintsEnabledScalar() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("RLADKR_APDB_PAYLOAD_HINTS"))) {
	case "1", "true", "on", "enabled":
		return true
	default:
		return false
	}
}

// CVPayloadHintsEnabled reports the component-recovery wire profile used by
// the benchmark process. Hints are an optional verified decode acceleration.
func CVPayloadHintsEnabled() bool {
	return cvPayloadHintsEnabledScalar()
}

// cvMaxPayloadHintsBytesScalar bounds the attachment: hints hold 96 bytes per
// deferred point while the payload carries at least 48 canonical bytes for
// each, so twice the payload limit is a safe upper bound.
func cvMaxPayloadHintsBytesScalar(maximumPayload int) int {
	if maximumPayload <= 0 {
		return 0
	}
	return 2 * maximumPayload
}
