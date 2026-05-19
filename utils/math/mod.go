package math

import (
	"math/big"
	"math/bits"
)

// MForm switches a to the Montgomery domain by computing a*2^64 mod q.
func MForm(a, q uint64, u []uint64) (r uint64) {
	mhi, _ := bits.Mul64(a, u[1])
	r = -(a*u[0] + mhi) * q
	if r >= q {
		r -= q
	}
	return
}

func MFormConstant(a, q uint64, u []uint64) (r uint64) {
	mhi, _ := bits.Mul64(a, u[1])
	r = -(a*u[0] + mhi) * q
	return
}

func InvMForm(a, q, qInv uint64) (r uint64) {
	r, _ = bits.Mul64(a*qInv, q)
	r = q - r
	if r >= q {
		r -= q
	}
	return
}

func InvMFormConstant(a, q, qInv uint64) (r uint64) {
	r, _ = bits.Mul64(a*qInv, q)
	r = q - r
	return
}

func MRedParams(q uint64) (qInv uint64) {
	qInv = 1
	for i := 0; i < 63; i++ {
		qInv *= q
		q *= q
	}
	return
}

func MRed(x, y, q, qInv uint64) (r uint64) {
	mhi, mlo := bits.Mul64(x, y)
	hhi, _ := bits.Mul64(mlo*qInv, q)
	r = mhi - hhi + q
	if r >= q {
		r -= q
	}
	return
}

func MRedConstant(x, y, q, qInv uint64) (r uint64) {
	ahi, alo := bits.Mul64(x, y)
	H, _ := bits.Mul64(alo*qInv, q)
	r = ahi - H + q
	return
}

func BRedParams(q uint64) (params []uint64) {
	bigR := new(big.Int).Lsh(NewUint(1), 128)
	bigR.Quo(bigR, NewUint(q))
	mhi := new(big.Int).Rsh(bigR, 64).Uint64()
	mlo := bigR.Uint64()
	return []uint64{mhi, mlo}
}

func BRedAdd(a, q uint64, u []uint64) (r uint64) {
	mhi, _ := bits.Mul64(a, u[0])
	r = a - mhi*q
	if r >= q {
		r -= q
	}
	return
}

func BRedAddConstant(x, q uint64, u []uint64) uint64 {
	s0, _ := bits.Mul64(x, u[0])
	return x - s0*q
}

func BRed(x, y, q uint64, u []uint64) (r uint64) {
	var mhi, mlo, lhi, hhi, hlo, s0, carry uint64
	mhi, mlo = bits.Mul64(x, y)
	r = mhi * u[0]
	hhi, hlo = bits.Mul64(mlo, u[0])
	r += hhi
	lhi, _ = bits.Mul64(mlo, u[1])
	s0, carry = bits.Add64(hlo, lhi, 0)
	r += carry
	hhi, hlo = bits.Mul64(mhi, u[1])
	r += hhi
	_, carry = bits.Add64(hlo, s0, 0)
	r += carry
	r = mlo - r*q
	if r >= q {
		r -= q
	}
	return
}

func BRedConstant(x, y, q uint64, u []uint64) (r uint64) {
	var mhi, mlo, lhi, hhi, hlo, s0, carry uint64
	mhi, mlo = bits.Mul64(x, y)
	r = mhi * u[0]
	hhi, hlo = bits.Mul64(mlo, u[0])
	r += hhi
	lhi, _ = bits.Mul64(mlo, u[1])
	s0, carry = bits.Add64(hlo, lhi, 0)
	r += carry
	hhi, hlo = bits.Mul64(mhi, u[1])
	r += hhi
	_, carry = bits.Add64(hlo, s0, 0)
	r += carry
	r = mlo - r*q
	return
}

func CRed(a, q uint64) uint64 {
	if a >= q {
		return a - q
	}
	return a
}

// PowerOf2 returns (x*2^n)%q where x is in Montgomery form
func PowerOf2(x uint64, n int, q, qInv uint64) (r uint64) {
	ahi, alo := x>>(64-n), x<<n
	R := alo * qInv
	H, _ := bits.Mul64(R, q)
	r = ahi - H + q
	if r >= q {
		r -= q
	}
	return
}

// ModexpMontgomery performs the modular exponentiation x^e mod p,
// where x is in Montgomery form, and returns x^e in Montgomery form.
func ModexpMontgomery(x uint64, e int, q, qInv uint64, bredParams []uint64) (result uint64) {
	result = MForm(1, q, bredParams)
	for i := e; i > 0; i >>= 1 {
		if i&1 == 1 {
			result = MRed(result, x, q, qInv)
		}
		x = MRed(x, x, q, qInv)
	}
	return result
}
