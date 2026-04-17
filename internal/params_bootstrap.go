package internal

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const DefaultSigma = 3.2

type LegacySinType uint64

const (
	LegacySin = LegacySinType(iota)
	LegacyCos1
	LegacyCos2
)

type ModDownPlan struct {
	CipherModDown []int
	StCModDown    []int
}

type LegacySineEvalModuli struct {
	Qi            []uint64
	ScalingFactor float64
}

type LegacyCoeffsToSlotsModuli struct {
	Qi            []uint64
	ScalingFactor [][]float64
}

// LegacyHalfBootParameters mirrors the data carried by the _old RtF presets while
// offering adapters to the public lattigo/v6 APIs.
type LegacyHalfBootParameters struct {
	ResidualModuli      []uint64
	KeySwitchModuli     []uint64
	SineEvalModuli      LegacySineEvalModuli
	DiffScaleModulus    []uint64
	CoeffsToSlotsModuli LegacyCoeffsToSlotsModuli
	LogN                int
	LogSlots            int
	PlainModulus        uint64
	Scale               float64
	Sigma               float64
	H                   int
	SinType             LegacySinType
	MessageRatio        float64
	SinRange            int
	SinDeg              int
	SinRescal           int
	ArcSineDeg          int
	MaxN1N2Ratio        float64
}

func (p LegacyHalfBootParameters) WithPlainModulus(plainModulus uint64) LegacyHalfBootParameters {
	p.PlainModulus = plainModulus
	return p
}

func (p LegacyHalfBootParameters) LogDefaultScale() int {
	return int(math.Round(math.Log2(p.Scale)))
}

func (p LegacyHalfBootParameters) LogMessageRatio() int {
	return int(math.Round(math.Log2(p.MessageRatio)))
}

func (p LegacyHalfBootParameters) Prescale() float64 {
	return math.Exp2(math.Round(math.Log2(float64(p.ResidualModuli[0]) / p.MessageRatio)))
}

func (p LegacyHalfBootParameters) ResidualLiteral() ckks.ParametersLiteral {
	return ckks.ParametersLiteral{
		LogN:            p.LogN,
		Q:               append([]uint64(nil), p.ResidualModuli...),
		P:               append([]uint64(nil), p.KeySwitchModuli...),
		Xs:              ring.Ternary{H: p.H},
		LogDefaultScale: p.LogDefaultScale(),
	}
}

func (p LegacyHalfBootParameters) ResidualParameters() (ckks.Parameters, error) {
	params, err := ckks.NewParametersFromLiteral(p.ResidualLiteral())
	if err != nil {
		return ckks.Parameters{}, fmt.Errorf("new CKKS residual parameters: %w", err)
	}
	return params, nil
}

func (p LegacyHalfBootParameters) BootstrappingLiteral() bootstrapping.ParametersLiteral {
	logSlots := p.LogSlots
	evalModLogScale := 60
	if len(p.SineEvalModuli.Qi) > 0 {
		evalModLogScale = bits.Len64(p.SineEvalModuli.Qi[0]) - 1
	}

	lit := bootstrapping.ParametersLiteral{
		LogN:     intPtr(p.LogN),
		LogP:     bitLens(p.KeySwitchModuli),
		Xs:       ring.Ternary{H: p.H},
		LogSlots: intPtr(logSlots),
		CoeffsToSlotsFactorizationDepthAndLogScales: p.coeffsToSlotsLogScales(),
		EvalModLogScale: intPtr(evalModLogScale),
		LogMessageRatio: intPtr(p.LogMessageRatio()),
		K:               intPtr(p.SinRange),
		Mod1Degree:      intPtr(p.SinDeg),
		DoubleAngle:     intPtr(p.SinRescal),
		Mod1InvDegree:   intPtr(p.ArcSineDeg),
	}

	switch p.SinType {
	case LegacySin:
		lit.Mod1Type = mod1.SinContinuous
	case LegacyCos2:
		lit.Mod1Type = mod1.CosContinuous
	default:
		lit.Mod1Type = mod1.CosDiscrete
	}

	return lit
}

func (p LegacyHalfBootParameters) BootstrappingParameters() (bootstrapping.Parameters, error) {
	residual, err := p.ResidualParameters()
	if err != nil {
		return bootstrapping.Parameters{}, err
	}

	params, err := bootstrapping.NewParametersFromLiteral(residual, p.BootstrappingLiteral())
	if err != nil {
		return bootstrapping.Parameters{}, fmt.Errorf("new aes_bootstrapping parameters: %w", err)
	}
	return params, nil
}

func (p LegacyHalfBootParameters) coeffsToSlotsLogScales() [][]int {
	out := make([][]int, len(p.CoeffsToSlotsModuli.ScalingFactor))
	for i, level := range p.CoeffsToSlotsModuli.ScalingFactor {
		logScale := bits.Len64(p.CoeffsToSlotsModuli.Qi[i]) - 1
		out[i] = make([]int, len(level))
		for j := range level {
			out[i][j] = logScale
		}
	}
	return out
}

func bitLens(moduli []uint64) []int {
	out := make([]int, len(moduli))
	for i, modulus := range moduli {
		out[i] = bits.Len64(modulus)
	}
	return out
}

func intPtr(v int) *int {
	return &v
}
