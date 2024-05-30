package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/rangecheck"
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

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

type PreBlockCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit *PreBlockCircuit) Define(api frontend.API) error {

	var _upper big.Int
	_upper.SetString("1000000000000000000000000000000000000000", 16) // 2^160

	rangeChecker := rangecheck.New(api)

	cmprtr := cmp.NewBoundedComparator(api, &_upper, false)

	// Comparison
	for i := 0; i < 1280; i++ {
		res := cmprtr.IsLess(circuit.Y, circuit.X)
		api.AssertIsEqual(res, 1)
	}

	// Asserted Comparison
	for i := 0; i < 1024; i++ {
		cmprtr.AssertIsLess(circuit.Y, circuit.X)
	}

	// Integer division
	for i := 0; i < 256; i++ {
		FloorDiv(api, circuit.X, circuit.Y)
	}

	// IsNegative
	for i := 0; i < 256; i++ {
		rangeChecker.Check(circuit.X, 160)
	}

	return nil
}

func PreBlock() {

	var _upper_minus_one big.Int
	_upper_minus_one.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // 2^160 - 1

	var _y big.Int
	_y.SetString("FFFFFFFFFFFFFFF", 16)

	circuit := PreBlockCircuit{
		X: _upper_minus_one,
		Y: _y,
	}

	r1cs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(),
	)
	if err != nil {
		panic(err)
	}

	r1csAsCS, ok := r1cs.(*cs.R1CS)
	if !ok {
		panic("Failed to assert r1cs to *constraint.R1CS")
	}

	fmt.Println("####### Setting up")
	pk := groth16.ProvingKey{}
	vk := groth16.VerifyingKey{}

	err = groth16.Setup(r1csAsCS, &pk, &vk)
	if err != nil {
		panic(err)
	}

	fmt.Println("####### Assigning witness")
	witness, err := frontend.NewWitness(&PreBlockCircuit{
		X: _upper_minus_one,
		Y: _y,
	}, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	totalProvingTime := time.Duration(0)
	totalVerifyingTime := time.Duration(0)
	numIterations := 1

	for i := 0; i < numIterations; i++ {
		fmt.Println("####### Proving")

		startTime := time.Now()
		proof, err := groth16.Prove(r1csAsCS, &pk, witness, backend.WithSolverOptions(solver.WithHints(IntegerDivision)))
		if err != nil {
			panic(err)
		}
		totalProvingTime += time.Since(startTime)

		fmt.Println("####### Verify")

		pubWitness, _ := witness.Public()
		pubVector := pubWitness.Vector()

		vector, ok := pubVector.(fr.Vector)
		if !ok {
			panic("pubVector is not of type fr.Vector")
		}

		startTime = time.Now()
		err = groth16.Verify(proof, &vk, vector)
		if err != nil {
			panic(err)
		}
		totalVerifyingTime += time.Since(startTime)
	}
}

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

type TxLoopCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit *TxLoopCircuit) Define(api frontend.API) error {

	var _upper big.Int
	_upper.SetString("1000000000000000000000000000000000000000", 16) // 2^160

	rangeChecker := rangecheck.New(api)

	cmprtr := cmp.NewBoundedComparator(api, &_upper, false)

	// Native MiMC
	nativeMimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	for i := 0; i < 16; i++ {
		nativeMimc.Reset()
		nativeMimc.Write(circuit.X)
		hRAM := nativeMimc.Sum()
		Q := curve.DoubleBaseScalarMul(base, base, circuit.X, hRAM)
		curve.AssertIsOnCurve(Q)
	}

	// gkr mimc
	bN, err := ChooseBN(4)
	if err != nil {
		return err
	}
	gkrMimc := NewMimcGKR(api, bN)

	var hash frontend.Variable
	for i := 0; i < 5582; i++ {
		hash = MimcWithGkr(
			gkrMimc,
			circuit.X,
			circuit.Y,
		)
	}
	gkrMimc.VerifyGKRMimc(hash)

	// Poseidon
	for i := 0; i < 66; i++ {
		Poseidon(api, circuit.X, circuit.Y)
	}

	// Comparison
	for i := 0; i < 49; i++ {
		res := cmprtr.IsLess(circuit.Y, circuit.X)
		api.AssertIsEqual(res, 1)
	}

	// Asserted Comparison
	for i := 0; i < 19; i++ {
		cmprtr.AssertIsLess(circuit.Y, circuit.X)
	}

	// IsNegative
	for i := 0; i < 6; i++ {
		rangeChecker.Check(circuit.X, 160)
	}

	// Integer division
	for i := 0; i < 13; i++ {
		FloorDiv(api, circuit.X, circuit.Y)
	}

	var x_bits []frontend.Variable
	// ToBinary
	for i := 0; i < 65; i++ {
		x_bits = bits.ToBinary(api, circuit.X)
	}

	// FromBinary
	for i := 0; i < 236; i++ {
		x_from_binary := bits.FromBinary(api, x_bits)
		api.AssertIsEqual(circuit.X, x_from_binary)
	}

	return nil
}

func TxLoop() {

	var _upper_minus_one big.Int
	_upper_minus_one.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // 2^160 - 1

	var _y big.Int
	_y.SetString("FFFFFFFFFFFFFFF", 16)

	circuit := TxLoopCircuit{
		X: _upper_minus_one,
		Y: _y,
	}

	r1cs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(),
	)
	if err != nil {
		panic(err)
	}

	r1csAsCS, ok := r1cs.(*cs.R1CS)
	if !ok {
		panic("Failed to assert r1cs to *constraint.R1CS")
	}

	fmt.Println("####### Setting up")
	pk := groth16.ProvingKey{}
	vk := groth16.VerifyingKey{}

	err = groth16.Setup(r1csAsCS, &pk, &vk)
	if err != nil {
		panic(err)
	}

	fmt.Println("####### Assigning witness")
	witness, err := frontend.NewWitness(&TxLoopCircuit{
		X: _upper_minus_one,
		Y: _y,
	}, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	totalProvingTime := time.Duration(0)
	totalVerifyingTime := time.Duration(0)
	numIterations := 1

	for i := 0; i < numIterations; i++ {
		fmt.Println("####### Proving")

		startTime := time.Now()
		proof, err := groth16.Prove(r1csAsCS, &pk, witness, backend.WithSolverOptions(solver.WithHints(MIMC2Elements, IntegerDivision)))
		if err != nil {
			panic(err)
		}
		totalProvingTime += time.Since(startTime)

		fmt.Println("####### Verify")

		pubWitness, _ := witness.Public()
		pubVector := pubWitness.Vector()

		vector, ok := pubVector.(fr.Vector)
		if !ok {
			panic("pubVector is not of type fr.Vector")
		}

		startTime = time.Now()
		err = groth16.Verify(proof, &vk, vector)
		if err != nil {
			panic(err)
		}
		totalVerifyingTime += time.Since(startTime)
	}
}

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

type StateRootCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit *StateRootCircuit) Define(api frontend.API) error {

	return nil
}

func StateRoot() {

}

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

func main() {
	if len(os.Args) > 1 {
		arg, err := strconv.Atoi(os.Args[1])
		if err != nil {
			panic(err)
		}

		if arg == 0 {
			PreBlock()
		} else if arg == 1 {
			TxLoop()
		} else {
			StateRoot()
		}
	}
}
