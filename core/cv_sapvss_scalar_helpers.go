package core

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

const cvComponentPayloadDigestScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/component-payload"

// cvComponentPayloadDigestScalar binds a component payload to its wire digest.
// This helper is shared by the network pipeline and APDB scaling checks.
func cvComponentPayloadDigestScalar(payload []byte) []byte {
	return hashBytes([]byte(cvComponentPayloadDigestScalarDomain), payload)
}

func cvEvaluateScalarPolynomialScalar(coefficients []fr.Element, receiverIndex int) fr.Element {
	var x fr.Element
	x.SetInt64(int64(receiverIndex))
	powers := cvFrPowers(x, len(coefficients))
	var result fr.Element
	for i := range coefficients {
		var term fr.Element
		term.Mul(&coefficients[i], &powers[i])
		result.Add(&result, &term)
	}
	return result
}
