package pasta

import (
	"github.com/hosseinabdinf/sherdal/pkg"

	sympasta "github.com/hosseinabdinf/sherdal/ske/pasta"
)

type Preset int

const (
	Pasta3_1614 Preset = iota
	Pasta3_3215
	Pasta3_6015
	Pasta4_1614
	Pasta4_3215
	Pasta4_6015
)

type Config struct {
	Preset          Preset
	BGVLogN         int
	UseResidualBGV  bool
	SymmetricParams sympasta.Parameter
}

func DefaultPastaConfig(preset Preset, symParams sympasta.Parameter) Config {
	return Config{Preset: preset, BGVLogN: 15, SymmetricParams: symParams}
}

func (cfg Config) halfBootSpec() pkg.LegacyHalfBootParameters {
	spec := pastaHalfBootPreset
	if cfg.SymmetricParams.Modulus != 0 {
		spec = spec.WithPlainModulus(cfg.SymmetricParams.Modulus)
	}
	return spec
}

func (cfg Config) modDownPlan() pkg.ModDownPlan {
	return pastaModDown[cfg.Preset]
}

var pastaModDown = []pkg.ModDownPlan{
	{CipherModDown: []int{12, 0, 1}, StCModDown: []int{1, 0, 2, 0, 1, 1, 1, 1}},
	{CipherModDown: []int{13, 0, 1}, StCModDown: []int{2, 0, 1, 1, 0, 1, 1, 1}},
	{CipherModDown: []int{13, 0, 1}, StCModDown: []int{2, 0, 1, 1, 0, 1, 1, 1}},
	{CipherModDown: []int{10, 0, 1, 1, 1, 1}, StCModDown: []int{1, 1, 1, 0, 1, 1, 1, 0}},
	{CipherModDown: []int{12, 0, 1, 1}, StCModDown: []int{2, 0, 1, 1, 0, 1, 1, 1}},
	{CipherModDown: []int{13, 0, 1}, StCModDown: []int{2, 0, 1, 1, 0, 1, 1, 1}},
}

// using rubatoHalfBootPreset as requested by the user
var pastaHalfBootPreset = pkg.LegacyHalfBootParameters{
	LogN:                16,
	LogSlots:            15,
	Scale:               1 << 45,
	Sigma:               pkg.DefaultSigma,
	PlainModulus:        sympasta.Pasta4Param1614.Modulus,
	ResidualModuli:      []uint64{0x10000000006e0001, 0x2000000a0001, 0x2000000e0001, 0x1fffffc20001, 0x200000440001, 0x200000500001, 0x200000620001, 0x1fffff980001},
	KeySwitchModuli:     []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001},
	DiffScaleModulus:    []uint64{0x2a0001},
	SineEvalModuli:      pkg.LegacySineEvalModuli{Qi: []uint64{0xffffffffffc0001, 0xfffffffff240001, 0x1000000000f00001, 0xfffffffff840001, 0x1000000000860001, 0xfffffffff6a0001, 0x1000000000980001, 0xfffffffff5a0001, 0x1000000000b00001, 0x1000000000ce0001, 0xfffffffff2a0001}, ScalingFactor: 1 << 60},
	CoeffsToSlotsModuli: pkg.LegacyCoeffsToSlotsModuli{Qi: []uint64{0x400000000360001, 0x3ffffffffbe0001, 0x400000000660001, 0x4000000008a0001}, ScalingFactor: [][]float64{{0x400000000360001}, {0x3ffffffffbe0001}, {0x400000000660001}, {0x4000000008a0001}}},
	H:                   192, SinType: pkg.LegacyCos1, MessageRatio: 16.0, SinRange: 25, SinDeg: 63, SinRescal: 2, ArcSineDeg: 7, MaxN1N2Ratio: 16.0,
}
