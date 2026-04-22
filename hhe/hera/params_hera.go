package hera

import (
	"github.com/hosseinabdinf/sherdal/internal"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"
)

type HeraPreset int

const (
	Hera128F HeraPreset = iota
	Hera128S
	Hera128AF
	Hera128AS
)

type Config struct {
	Preset          HeraPreset
	BGVLogN         int
	UseResidualBGV  bool
	SymmetricParams symhera.Parameter
}

func DefaultHeraConfig(preset HeraPreset, symParams symhera.Parameter) Config {
	return Config{Preset: preset, BGVLogN: 15, SymmetricParams: symParams}
}

func (cfg Config) HalfBootSpec() internal.LegacyHalfBootParameters {
	spec := heraHalfBootPresets[cfg.Preset]
	if cfg.SymmetricParams.Modulus != 0 {
		spec = spec.WithPlainModulus(cfg.SymmetricParams.Modulus)
	}
	return spec
}

func (cfg Config) modDownPlan() internal.ModDownPlan {
	if cfg.SymmetricParams.Rounds == 4 {
		return heraModDown80[cfg.Preset]
	}
	return heraModDown128[cfg.Preset]
}

func (cfg Config) fullCoefficients() bool {
	switch cfg.Preset {
	case Hera128F, Hera128AF:
		return true
	default:
		return false
	}
}

func (cfg Config) logFVSlots() int {
	if cfg.fullCoefficients() {
		return cfg.HalfBootSpec().LogN
	}
	return cfg.HalfBootSpec().LogSlots
}

var heraModDown80 = []internal.ModDownPlan{
	{CipherModDown: []int{6, 2, 2, 2, 3}, StCModDown: []int{1, 0, 1, 1, 1, 1, 1, 1}},
	{CipherModDown: []int{10, 2, 3, 3, 3}, StCModDown: []int{0}},
	{CipherModDown: []int{7, 2, 2, 2, 2}, StCModDown: []int{1, 1, 0, 1, 1, 1, 0, 0}},
	{CipherModDown: []int{11, 2, 2, 3, 2}, StCModDown: []int{0}},
}

var heraModDown128 = []internal.ModDownPlan{
	{CipherModDown: []int{4, 2, 2, 2, 2, 3}, StCModDown: []int{0, 1, 1, 1, 1, 1, 1, 1}},
	{CipherModDown: []int{9, 2, 3, 3, 3, 2}, StCModDown: []int{1}},
	{CipherModDown: []int{5, 2, 2, 2, 2, 2}, StCModDown: []int{1, 1, 0, 1, 1, 1, 0, 0}},
	{CipherModDown: []int{9, 2, 2, 2, 3, 2}, StCModDown: []int{0, 1}},
}

var heraHalfBootPresets = []internal.LegacyHalfBootParameters{
	{
		LogN:                16,
		LogSlots:            15,
		Scale:               1 << 40,
		PlainModulus:        268042241,
		Sigma:               internal.DefaultSigma,
		ResidualModuli:      []uint64{0x10000000006e0001, 0x10000140001, 0xffffe80001, 0xffffc40001, 0x100003e0001, 0xffffb20001, 0x10000500001, 0xffff940001, 0xffff8a0001, 0xffff820001, 0xffff780001, 0x10000960001},
		KeySwitchModuli:     []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff420001},
		DiffScaleModulus:    []uint64{0xfc0001},
		SineEvalModuli:      internal.LegacySineEvalModuli{Qi: []uint64{0xfffffffff840001, 0x1000000000860001, 0xfffffffff6a0001, 0x1000000000980001, 0xfffffffff5a0001, 0x1000000000b00001, 0x1000000000ce0001, 0xfffffffff2a0001}, ScalingFactor: 1 << 60},
		CoeffsToSlotsModuli: internal.LegacyCoeffsToSlotsModuli{Qi: []uint64{0x100000000060001, 0xfffffffff00001, 0xffffffffd80001, 0x1000000002a0001}, ScalingFactor: [][]float64{{0x100000000060001}, {0xfffffffff00001}, {0xffffffffd80001}, {0x1000000002a0001}}},
		H:                   192, SinType: internal.LegacyCos1, MessageRatio: 512.0, SinRange: 25, SinDeg: 63, SinRescal: 2, ArcSineDeg: 0, MaxN1N2Ratio: 16.0,
	},
	{
		LogN:                16,
		LogSlots:            4,
		Scale:               1 << 40,
		PlainModulus:        268042241,
		Sigma:               internal.DefaultSigma,
		ResidualModuli:      []uint64{0x10000000006e0001, 0x10000140001, 0xffffe80001, 0xffffc40001, 0x100003e0001, 0xffffb20001, 0x10000500001, 0xffff940001, 0xffff8a0001, 0xffff820001, 0xffff780001, 0x10000960001},
		KeySwitchModuli:     []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff420001},
		DiffScaleModulus:    []uint64{0xfc0001},
		SineEvalModuli:      internal.LegacySineEvalModuli{Qi: []uint64{0xfffffffff840001, 0x1000000000860001, 0xfffffffff6a0001, 0x1000000000980001, 0xfffffffff5a0001, 0x1000000000b00001, 0x1000000000ce0001, 0xfffffffff2a0001}, ScalingFactor: 1 << 60},
		CoeffsToSlotsModuli: internal.LegacyCoeffsToSlotsModuli{Qi: []uint64{0x100000000060001, 0xfffffffff00001, 0xffffffffd80001, 0x1000000002a0001}, ScalingFactor: [][]float64{{0x100000000060001}, {0xfffffffff00001}, {0xffffffffd80001}, {0x1000000002a0001}}},
		H:                   192, SinType: internal.LegacyCos1, MessageRatio: 512.0, SinRange: 25, SinDeg: 63, SinRescal: 2, ArcSineDeg: 0, MaxN1N2Ratio: 16.0,
	},
	{
		LogN:                16,
		LogSlots:            15,
		Scale:               1 << 45,
		PlainModulus:        33292289,
		Sigma:               internal.DefaultSigma,
		ResidualModuli:      []uint64{0x10000000006e0001, 0x2000000a0001, 0x2000000e0001, 0x1fffffc20001, 0x200000440001, 0x200000500001, 0x200000620001, 0x1fffff980001},
		KeySwitchModuli:     []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001},
		DiffScaleModulus:    []uint64{0x2a0001},
		SineEvalModuli:      internal.LegacySineEvalModuli{Qi: []uint64{0xffffffffffc0001, 0xfffffffff240001, 0x1000000000f00001, 0xfffffffff840001, 0x1000000000860001, 0xfffffffff6a0001, 0x1000000000980001, 0xfffffffff5a0001, 0x1000000000b00001, 0x1000000000ce0001, 0xfffffffff2a0001}, ScalingFactor: 1 << 60},
		CoeffsToSlotsModuli: internal.LegacyCoeffsToSlotsModuli{Qi: []uint64{0x400000000360001, 0x3ffffffffbe0001, 0x400000000660001, 0x4000000008a0001}, ScalingFactor: [][]float64{{0x400000000360001}, {0x3ffffffffbe0001}, {0x400000000660001}, {0x4000000008a0001}}},
		H:                   192, SinType: internal.LegacyCos1, MessageRatio: 16.0, SinRange: 25, SinDeg: 63, SinRescal: 2, ArcSineDeg: 7, MaxN1N2Ratio: 16.0,
	},
	{
		LogN:                16,
		LogSlots:            4,
		Scale:               1 << 45,
		PlainModulus:        33292289,
		Sigma:               internal.DefaultSigma,
		ResidualModuli:      []uint64{0x10000000006e0001, 0x2000000a0001, 0x2000000e0001, 0x1fffffc20001, 0x200000440001, 0x200000500001, 0x200000620001, 0x1fffff980001},
		KeySwitchModuli:     []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001},
		DiffScaleModulus:    []uint64{0x2a0001},
		SineEvalModuli:      internal.LegacySineEvalModuli{Qi: []uint64{0xffffffffffc0001, 0xfffffffff240001, 0x1000000000f00001, 0xfffffffff840001, 0x1000000000860001, 0xfffffffff6a0001, 0x1000000000980001, 0xfffffffff5a0001, 0x1000000000b00001, 0x1000000000ce0001, 0xfffffffff2a0001}, ScalingFactor: 1 << 60},
		CoeffsToSlotsModuli: internal.LegacyCoeffsToSlotsModuli{Qi: []uint64{0x400000000360001, 0x3ffffffffbe0001, 0x400000000660001, 0x4000000008a0001}, ScalingFactor: [][]float64{{0x400000000360001}, {0x3ffffffffbe0001}, {0x400000000660001}, {0x4000000008a0001}}},
		H:                   192, SinType: internal.LegacyCos1, MessageRatio: 16.0, SinRange: 25, SinDeg: 63, SinRescal: 2, ArcSineDeg: 7, MaxN1N2Ratio: 16.0,
	},
}
