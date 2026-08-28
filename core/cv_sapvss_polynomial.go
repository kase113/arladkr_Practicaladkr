package core

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

func evalPolyInt(coefficients []fr.Element, x int64) fr.Element {
	var point fr.Element
	point.SetInt64(x)
	if len(coefficients) == 0 {
		return fr.Element{}
	}
	result := coefficients[len(coefficients)-1]
	for index := len(coefficients) - 2; index >= 0; index-- {
		result.Mul(&result, &point)
		result.Add(&result, &coefficients[index])
	}
	return result
}
