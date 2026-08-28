package core

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type cvVerifiedReceipt struct {
	receiverID int
	index      int
	wire       []byte
	receipt    *cvReceipt
}

type cvPreparedReceiptOutputs struct {
	shares   map[int][]byte
	receipts map[int][]byte
	verified map[int]*cvVerifiedReceipt
}

func cvPrepareLocalDecryptionOutputs(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (*cvPreparedReceiptOutputs, error) {
	indices, err := cvReceiverIndices(context, receiverOrder)
	if err != nil {
		return nil, err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return nil, err
	}
	outputs := &cvPreparedReceiptOutputs{
		shares: make(map[int][]byte, len(localSecrets)), receipts: make(map[int][]byte, len(localSecrets)),
		verified: make(map[int]*cvVerifiedReceipt, len(localSecrets)),
	}
	for receiverID, secret := range localSecrets {
		index, ok := indices[receiverID]
		if !ok {
			return nil, fmt.Errorf("local CV-sAPVSS receiver %d is outside the roster", receiverID)
		}
		decrypted, receipt, err := cvDecShareVerifiedAggregate(agg, secret, index)
		if err != nil {
			return nil, err
		}
		if err := cvVerifyShareVerifiedAggregate(context, agg, index, receipt); err != nil {
			return nil, err
		}
		encodedShare := decrypted.scalar.Bytes()
		outputs.shares[receiverID] = append([]byte(nil), encodedShare[:]...)
		receiptWire, err := cvReceiptCanonicalBytes(receipt)
		if err != nil {
			return nil, err
		}
		outputs.receipts[receiverID] = receiptWire
		outputs.verified[receiverID] = &cvVerifiedReceipt{
			receiverID: receiverID, index: index, wire: receiptWire, receipt: receipt,
		}
	}
	return outputs, nil
}

func cvCreateLocalDecryptionOutputs(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (map[int][]byte, map[int][]byte, error) {
	outputs, err := cvPrepareLocalDecryptionOutputs(context, agg, receiverOrder, localSecrets)
	if err != nil {
		return nil, nil, err
	}
	return outputs.shares, outputs.receipts, nil
}

func cvThresholdPublicKeyFromReceipts(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	receiptWires map[int][]byte,
) ([]byte, error) {
	indices, err := cvReceiverIndices(context, receiverOrder)
	if err != nil {
		return nil, err
	}
	verifiedTokens := make(map[int]*cvVerifiedReceipt, len(receiptWires))
	for receiverID, wire := range receiptWires {
		index, ok := indices[receiverID]
		if !ok {
			return nil, fmt.Errorf("CV-sAPVSS receipt receiver %d is outside the roster", receiverID)
		}
		receipt, err := cvDecodeReceipt(wire, context, agg, index)
		if err != nil {
			return nil, err
		}
		verifiedTokens[receiverID] = &cvVerifiedReceipt{
			receiverID: receiverID, index: index, wire: wire, receipt: receipt,
		}
	}
	return cvThresholdPublicKeyFromVerifiedReceipts(context, agg, receiverOrder, verifiedTokens)
}

func cvThresholdPublicKeyFromVerifiedReceipts(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	receipts map[int]*cvVerifiedReceipt,
) ([]byte, error) {
	indices, err := cvReceiverIndices(context, receiverOrder)
	if err != nil {
		return nil, err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return nil, err
	}
	threshold := context.sharingDegree + 1
	if threshold <= 0 || len(receipts) < threshold {
		return nil, fmt.Errorf("insufficient CV-sAPVSS public receipts: have=%d need=%d", len(receipts), threshold)
	}
	verified := make([]*cvVerifiedReceipt, 0, len(receipts))
	for receiverID, token := range receipts {
		index, ok := indices[receiverID]
		if !ok || token == nil || token.receipt == nil || token.receiverID != receiverID || token.index != index ||
			token.receipt.receiverIndex != index || !bytes.Equal(token.receipt.aggregateDigest, agg.digest) ||
			!bytes.Equal(token.wire, token.receipt.digestWire) {
			return nil, fmt.Errorf("invalid cached CV-sAPVSS receipt token for receiver %d", receiverID)
		}
		verified = append(verified, token)
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].index < verified[j].index })
	indicesAtZero := make([]int, len(verified))
	publicShares := make([]bls12381.G1Affine, len(verified))
	allFeldman := true
	for i := range verified {
		indicesAtZero[i] = verified[i].index
		publicShares[i] = verified[i].receipt.publicScalar
		if !verified[i].receipt.proof.feldman {
			allFeldman = false
		}
	}
	coefficients, err := cvLagrangeCoefficientsAtZero(indicesAtZero)
	if err != nil {
		return nil, err
	}
	publicKey, err := cvG1LinearCombination(publicShares, coefficients)
	if err != nil {
		return nil, err
	}
	var commitment bls12381.G1Affine
	if allFeldman {
		commitment = publicKey
	} else {
		blindingShares := make([]bls12381.G1Affine, len(verified))
		for i := range verified {
			if verified[i].receipt.proof.feldman {
				return nil, fmt.Errorf("mixed Feldman and Pedersen CV-sAPVSS receipts")
			}
			blindingShares[i] = verified[i].receipt.blindingOpening
		}
		blindingConstant, err := cvG1LinearCombination(blindingShares, coefficients)
		if err != nil {
			return nil, err
		}
		commitment.Add(&publicKey, &blindingConstant)
	}
	if len(agg.coefficientCommitments) == 0 || !commitment.Equal(&agg.coefficientCommitments[0]) {
		return nil, fmt.Errorf("CV-sAPVSS receipt interpolation does not match aggregate commitment")
	}
	if publicKey.IsInfinity() {
		return nil, fmt.Errorf("CV-sAPVSS threshold public key is identity")
	}
	encoded := publicKey.Bytes()
	return append([]byte(nil), encoded[:]...), nil
}

func cvLagrangeCoefficientsAtZero(indices []int) ([]fr.Element, error) {
	if len(indices) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS interpolation input")
	}
	seen := make(map[int]struct{}, len(indices))
	coefficients := make([]fr.Element, len(indices))
	for i, xI := range indices {
		if xI <= 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS interpolation index")
		}
		if _, duplicate := seen[xI]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS interpolation index")
		}
		seen[xI] = struct{}{}
		coefficients[i].SetOne()
		for j, xJ := range indices {
			if i == j {
				continue
			}
			var numerator, denominator fr.Element
			numerator.SetInt64(int64(xJ))
			denominator.SetInt64(int64(xJ - xI))
			if denominator.IsZero() {
				return nil, fmt.Errorf("duplicate CV-sAPVSS interpolation index")
			}
			denominator.Inverse(&denominator)
			numerator.Mul(&numerator, &denominator)
			coefficients[i].Mul(&coefficients[i], &numerator)
		}
	}
	return coefficients, nil
}

func cvG1LinearCombination(points []bls12381.G1Affine, coefficients []fr.Element) (bls12381.G1Affine, error) {
	if len(points) == 0 || len(points) != len(coefficients) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS interpolation input")
	}
	if len(points) >= 4 {
		var result bls12381.G1Affine
		// Inner MSM stays serial: every hot caller (leaf ownership batch,
		// subgroup batch) already runs inside the leaf-verify worker pool, and
		// gnark's task fan-out multiplies goroutines across those outer
		// workers while its channel coordination caps real utilization.
		if _, err := result.MultiExp(points, coefficients, ecc.MultiExpConfig{
			NbTasks: cvNestedMSMWorkers(len(points)),
		}); err == nil {
			return result, nil
		}
	}
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range points {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&points[i], coefficients[i].BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result, nil
}

func cvReceiverIndices(context *cvLeafContext, receiverOrder []int) (map[int]int, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(receiverOrder) != len(context.receiverPublicKeys) {
		return nil, fmt.Errorf("CV-sAPVSS receiver roster length mismatch")
	}
	indices := make(map[int]int, len(receiverOrder))
	for i, receiverID := range receiverOrder {
		if _, duplicate := indices[receiverID]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS receiver ID: %d", receiverID)
		}
		indices[receiverID] = i + 1
	}
	return indices, nil
}

func cvInterpolateG1AtZero(indices []int, points []bls12381.G1Affine) (bls12381.G1Affine, error) {
	if len(indices) == 0 || len(indices) != len(points) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS interpolation input")
	}
	coefficients, err := cvLagrangeCoefficientsAtZero(indices)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	return cvG1LinearCombination(points, coefficients)
}
