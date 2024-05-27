package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/rangecheck"
)

type MyCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit *MyCircuit) Define(api frontend.API) error {

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

func main() {

	var _upper_minus_one big.Int
	_upper_minus_one.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // 2^160 - 1

	var _y big.Int
	_y.SetString("FFFFFFFFFFFFFFF", 16)

	circuit := MyCircuit{
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

	////// 1

	fmt.Println("####### Assigning witness")
	witness, err := frontend.NewWitness(&MyCircuit{
		X: _upper_minus_one,
		Y: _y,
	}, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	fmt.Println("####### Proving")

	proof, err := groth16.Prove(r1csAsCS, &pk, witness, backend.WithSolverOptions(solver.WithHints(IntegerDivision)))
	if err != nil {
		panic(err)
	}

	////// 2

	fmt.Println("####### Verify")

	pubWitness, _ := witness.Public()
	pubVector := pubWitness.Vector()

	vector, ok := pubVector.(fr.Vector)
	if !ok {
		panic("pubVector is not of type fr.Vector")
	}

	err = groth16.Verify(proof, &vk, vector)
	if err != nil {
		panic(err)
	}
}
