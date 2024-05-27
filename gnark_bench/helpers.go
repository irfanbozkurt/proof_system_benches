package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

const ZeroInt = uint64(0)

var pow160 = new(big.Int).Lsh(new(big.Int).SetInt64(1), 160)

func IntegerDivision(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	dividend := inputs[0]
	divisor := inputs[1]
	zero := new(big.Int).SetInt64(0)
	if dividend.Cmp(zero) == -1 || divisor.Cmp(zero) == -1 {
		return fmt.Errorf("dividend or divisor is negative")
	}
	if !divisor.IsUint64() {
		return fmt.Errorf("divisor is not uint64")
	}
	outputs[0] = new(big.Int).SetInt64(0)
	outputs[1] = new(big.Int).SetInt64(0)
	if divisor.Cmp(zero) == 1 {
		outputs[0], outputs[1] = new(big.Int).DivMod(dividend, divisor, new(big.Int))
	}
	return nil
}

func AssertIsVariableEqual(api frontend.API, isEnabled, i1, i2 frontend.Variable) {
	zero := 0
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, zero)
	api.AssertIsEqual(i1, i2)
}

func AssertIsVariableDifferent(api frontend.API, isEnabled, i1, i2 frontend.Variable) {
	zero := 0
	one := 1
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, one)
	api.AssertIsDifferent(i1, i2)
}

func AssertIsVariableLessOrEqual(api frontend.API, isEnabled, i1, i2 frontend.Variable) {
	zero := 0
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, zero)
	api.AssertIsLessOrEqual(i1, i2)
}

func AssertIsVariableLess(api frontend.API, isEnabled, i1, i2 frontend.Variable) {
	zero := 0
	one := 1
	i1 = api.Select(isEnabled, i1, zero)
	i2 = api.Select(isEnabled, i2, one)
	api.AssertIsEqual(api.Cmp(i1, i2), -1)
}

func FloorDiv(api frontend.API, dividend, divisor frontend.Variable) frontend.Variable {
	// res[0] = quotient, res[1] = remainder
	res, _ := api.Compiler().NewHint(IntegerDivision, 2, dividend, divisor)
	isDivisorZero := api.IsZero(divisor)
	/// if divisor = 0, quotient = 0
	AssertIsVariableEqual(api, isDivisorZero, res[0], ZeroInt)

	isDivisorNonZero := api.IsZero(isDivisorZero)
	// if divisor != 0
	//   dividend = quotient * divisor + remainder
	//   0 <= remainder < divisor
	AssertIsVariableEqual(api, isDivisorNonZero, api.Add(api.Mul(res[0], divisor), res[1]), dividend)
	AssertIsVariableLess(api, isDivisorNonZero, res[1], divisor)

	// overflow checks
	// quotient * divisor is less than 2^160 * 2^64 = 2^224 << Prime
	AssertIsVariableLess(api, isDivisorNonZero, res[0], pow160)

	return res[0]
}

func RandomFieldElement(bitSize int) fr.Element {
	rand.Seed(time.Now().UnixNano())

	binaryString := ""

	for i := 256; i >= bitSize; i-- {
		binaryString = fmt.Sprintf("%s%d", binaryString, 0)
	}

	for i := bitSize - 1; i >= 0; i-- {
		binaryString = fmt.Sprintf("%s%d", binaryString, rand.Intn(2))
	}

	var e fr.Element
	e.SetString("0b" + binaryString)

	return e
}
