package internal

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// RtFBridge contains the narrow custom glue between the BGV keystream layer
// and the CKKS half-bootstrap input representation.
type RtFBridge struct {
	runtime        *BGVRuntime
	residual       ckks.Parameters
	plainModulus   uint64
	messageScaling float64
	q0             uint64
	deltaQ0        uint64
}

func NewRtFBridge(runtime *BGVRuntime, spec LegacyHalfBootParameters) (*RtFBridge, error) {
	residual, err := spec.ResidualParameters()
	if err != nil {
		return nil, err
	}

	if runtime.params.LogN() != residual.LogN() {
		return nil, fmt.Errorf("BGV logN %d does not match residual CKKS logN %d", runtime.params.LogN(), residual.LogN())
	}
	if runtime.params.PlaintextModulus() != spec.PlainModulus {
		return nil, fmt.Errorf("BGV plaintext modulus %d does not match bridge plain modulus %d", runtime.params.PlaintextModulus(), spec.PlainModulus)
	}
	if len(runtime.params.Q()) == 0 || runtime.params.Q()[0] != residual.Q()[0] {
		return nil, fmt.Errorf("BGV q0 must match residual CKKS q0")
	}

	q0 := residual.Q()[0]
	delta := new(big.Int).Quo(new(big.Int).SetUint64(q0), new(big.Int).SetUint64(spec.PlainModulus)).Uint64()

	return &RtFBridge{
		runtime:        runtime,
		residual:       residual,
		plainModulus:   spec.PlainModulus,
		messageScaling: float64(spec.PlainModulus) / spec.MessageRatio,
		q0:             q0,
		deltaQ0:        delta,
	}, nil
}

func (b *RtFBridge) MessageScaling() float64 {
	return b.messageScaling
}

func (b *RtFBridge) InputScale() float64 {
	return roundedScale(float64(b.q0) / float64(b.plainModulus) * b.messageScaling)
}

func (b *RtFBridge) EncodeCoefficientsRingT(values []float64) ([]uint64, error) {
	if len(values) > b.residual.N() {
		return nil, fmt.Errorf("too many coefficients: got %d, max %d", len(values), b.residual.N())
	}

	coeffs := make([]uint64, b.residual.N())
	for i, value := range values {
		coeffs[i] = scaleUpExactModT(value, b.messageScaling, b.plainModulus)
	}
	return coeffs, nil
}

func (b *RtFBridge) EncodeCoefficientsPlaintext(values []float64) (*rlwe.Plaintext, error) {
	ringT, err := b.EncodeCoefficientsRingT(values)
	if err != nil {
		return nil, err
	}
	return b.PlaintextFromRingT(ringT), nil
}

func (b *RtFBridge) BuildClientPlaintext(values []float64, keystreamCoeffs []uint64) (*rlwe.Plaintext, error) {
	ringT, err := b.EncodeCoefficientsRingT(values)
	if err != nil {
		return nil, err
	}
	if len(keystreamCoeffs) > len(ringT) {
		return nil, fmt.Errorf("keystream coefficient length %d exceeds ring size %d", len(keystreamCoeffs), len(ringT))
	}
	for i, coeff := range keystreamCoeffs {
		ringT[i] = (ringT[i] + coeff) % b.plainModulus
	}
	return b.PlaintextFromRingT(ringT), nil
}

func (b *RtFBridge) PlaintextFromRingT(coeffs []uint64) *rlwe.Plaintext {
	pt := bgv.NewPlaintext(b.runtime.params, 0)
	for i, coeff := range coeffs {
		pt.Value.Coeffs[0][i] = (coeff * b.deltaQ0) % b.q0
	}
	pt.Scale = b.runtime.params.DefaultScale()
	pt.IsNTT = false
	return pt
}

func (b *RtFBridge) EncryptCoefficientCiphertext(coeffs []uint64) (*rlwe.Ciphertext, error) {
	pt := b.PlaintextFromRingT(coeffs)
	ct, err := b.runtime.encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("encrypt coefficient plaintext: %w", err)
	}
	return ct, nil
}

func (b *RtFBridge) BuildHalfBootInput(values []float64, coeffCipher *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	pt, err := b.EncodeCoefficientsPlaintext(values)
	if err != nil {
		return nil, err
	}
	return b.BuildHalfBootInputFromPlaintext(pt, coeffCipher)
}

func (b *RtFBridge) BuildHalfBootInputFromPlaintext(pt *rlwe.Plaintext, coeffCipher *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if coeffCipher == nil {
		return nil, fmt.Errorf("coeffCipher is nil")
	}
	if coeffCipher.Level() > 0 {
		coeffCipher = coeffCipher.CopyNew()
		b.runtime.evaluator.DropLevel(coeffCipher, coeffCipher.Level())
	} else {
		coeffCipher = coeffCipher.CopyNew()
	}

	ringQ := b.residual.RingQ().AtLevel(0)
	toCoefficientDomain(ringQ, coeffCipher)

	ct := ckks.NewCiphertext(b.residual, coeffCipher.Degree(), 0)
	ct.Scale = rlwe.NewScale(b.InputScale())
	ct.LogDimensions = b.residual.LogMaxDimensions()
	ct.IsBatched = true
	ct.IsNTT = false

	ringQ.Sub(pt.Value, coeffCipher.Value[0], ct.Value[0])
	if len(ct.Value) > 1 {
		ringQ.Neg(coeffCipher.Value[1], ct.Value[1])
	}

	toNTTDomain(ringQ, ct)
	ct.IsNTT = true
	return ct, nil
}

func roundedScale(scale float64) float64 {
	return math.Exp2(math.Round(math.Log2(scale)))
}

func scaleUpExactModT(value float64, scale float64, modulus uint64) uint64 {
	var scaled *big.Float
	negative := value < 0
	if negative {
		scaled = big.NewFloat(-scale * value)
	} else {
		scaled = big.NewFloat(scale * value)
	}

	scaled.Add(scaled, big.NewFloat(0.5))
	integer := new(big.Int)
	scaled.Int(integer)
	integer.Mod(integer, new(big.Int).SetUint64(modulus))
	res := integer.Uint64()
	if negative && res != 0 {
		return modulus - res
	}
	return res
}

func toCoefficientDomain(ringQ *ring.Ring, ct *rlwe.Ciphertext) {
	if !ct.IsNTT {
		return
	}
	for i := range ct.Value {
		ringQ.INTT(ct.Value[i], ct.Value[i])
	}
	ct.IsNTT = false
}

func toNTTDomain(ringQ *ring.Ring, ct *rlwe.Ciphertext) {
	if ct.IsNTT {
		return
	}
	for i := range ct.Value {
		ringQ.NTT(ct.Value[i], ct.Value[i])
	}
	ct.IsNTT = true
}
