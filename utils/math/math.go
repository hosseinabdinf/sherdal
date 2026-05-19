package math

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
)

// RandUint64 return a random value between 0 and 0xFFFFFFFFFFFFFFFF
func RandUint64() uint64 {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b)
}

// RandFloat64 returns a random float between min and max
func RandFloat64(min, max float64) float64 {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	f := float64(binary.BigEndian.Uint64(b)) / 1.8446744073709552e+19
	return min + f*(max-min)
}

// RandComplex128 returns a random complex with the real and imaginary part between min and max
func RandComplex128(min, max float64) complex128 {
	return complex(RandFloat64(min, max), RandFloat64(min, max))
}

// MinUint64 returns the minimum value of the input of uint64 values.
func MinUint64(a, b uint64) (r uint64) {
	if a <= b {
		return a
	}
	return b
}

// MinInt returns the minimum value of the input of int values.
func MinInt(a, b int) (r int) {
	if a <= b {
		return a
	}
	return b
}

// MaxUint64 returns the maximum value of the input of uint64 values.
func MaxUint64(a, b uint64) (r uint64) {
	if a >= b {
		return a
	}
	return b
}

// MaxInt returns the maximum value of the input of int values.
func MaxInt(a, b int) (r int) {
	if a >= b {
		return a
	}
	return b
}

// MaxFloat64 returns the maximum value of the input slice of float64 values.
func MaxFloat64(a, b float64) (r float64) {
	if a >= b {
		return a
	}
	return b
}

// MaxSliceUint64 returns the maximum value of the input slice of uint64 values.
func MaxSliceUint64(slice []uint64) (max uint64) {
	for i := range slice {
		max = MaxUint64(max, slice[i])
	}
	return
}

// BitReverse64 returns the bit-reverse value of the input value, within a context of 2^bitLen.
func BitReverse64(index, bitLen uint64) uint64 {
	return bits.Reverse64(index) >> (64 - bitLen)
}

// HammingWeight64 returns the hammingweight if the input value.
func HammingWeight64(x uint64) uint64 {
	x -= (x >> 1) & 0x5555555555555555
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return ((x * 0x0101010101010101) & 0xffffffffffffffff) >> 56
}

// GCD computes the greatest common divisor gcd(a,b)
func GCD(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// ModExp performs modular exponentiation x^e mod p
func ModExp(x uint64, e int, p uint64) (result uint64) {
	params := BRedParams(p)
	result = 1
	for i := e; i > 0; i >>= 1 {
		if i&1 == 1 {
			result = BRed(result, x, p, params)
		}
		x = BRed(x, x, p, params)
	}
	return result
}

// IsPrime checks if a number is prime using Baillie-PSW (via big.Int.ProbablyPrime)
func IsPrime(x uint64) bool {
	return NewUint(x).ProbablyPrime(0)
}
