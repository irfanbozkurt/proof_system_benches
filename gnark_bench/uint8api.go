package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint8api performs binary operations on Xuint8 variables.
type Uint8api struct {
	api frontend.API
}

func NewUint8API(api frontend.API) *Uint8api {
	return &Uint8api{
		api: api,
	}
}

// Xuint8 represents 8-bit byte. We use this type to ensure that
// we work over constrained bits.
type Xuint8 [8]frontend.Variable

func ConstUint8(a uint8) Xuint8 {
	var res Xuint8
	for i := 0; i < 8; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *Uint8api) AsUint8FromBytes(in ...frontend.Variable) Xuint8 {
	return w.AsUint8(bits.FromBinary(w.api, in))
}

func (w *Uint8api) AsUint8(in frontend.Variable) Xuint8 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(8))
	var res Xuint8
	copy(res[:], bits)
	return res
}

func (w *Uint8api) DecodeToXuint32BigEndian(b []Xuint8) Xuint32 {
	var bits []frontend.Variable
	for i := 3; i >= 0; i-- {
		bits = append(bits, b[i][:]...)
	}

	var res Xuint32
	copy(res[:], bits[:])
	return res
}
