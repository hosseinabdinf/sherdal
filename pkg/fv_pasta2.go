package pkg

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	sym "github.com/hosseinabdinf/sherdal/ske"
	sympasta2 "github.com/hosseinabdinf/sherdal/ske/pasta2"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/sha3"
)

// FVPasta2Evaluator evaluates the Pasta v2 keystream over BGV.
type FVPasta2Evaluator struct {
	base           *baseCipher
	params         sympasta2.Parameter
	p              uint64
	inst           sympasta2.Instance
	mask           uint64
	noiseEstimator FVPasta2NoiseEstimator
	cfg            ParallelConfig
}

// FVPasta2NoiseEstimator can attach implementation-specific noise metrics to
// Pasta2 nonlinear-layer traces. Lattigo v6 does not expose a common BGV noise
// budget API, so callers that need noise logging provide the estimator.
type FVPasta2NoiseEstimator interface {
	EstimatePasta2Noise(layer string, round int, state []*rlwe.Ciphertext) (FVPasta2NoiseTrace, error)
}

// FVPasta2NoiseTrace records residual-noise norms after a nonlinear layer.
// Values are log2 norms returned by rlwe.Norm after subtracting an expected plaintext.
type FVPasta2NoiseTrace struct {
	MinStdLog2    float64
	MaxStdLog2    float64
	MinAbsMinLog2 float64
	MaxAbsMinLog2 float64
	MinAbsMaxLog2 float64
	MaxAbsMaxLog2 float64
}

// BGVResidualNoiseEstimator estimates BGV residual noise by decrypting, decoding,
// re-encoding the recovered plaintext, subtracting it, and calling rlwe.Norm.
// This is meaningful while decryption is still correct; once decoding fails, the
// recovered plaintext is not a reliable expected message.
type BGVResidualNoiseEstimator struct {
	runtime *BGVRuntime
}

func NewBGVResidualNoiseEstimator(runtime *BGVRuntime) *BGVResidualNoiseEstimator {
	return &BGVResidualNoiseEstimator{runtime: runtime}
}

func (e *BGVResidualNoiseEstimator) EstimatePasta2Noise(layer string, round int, state []*rlwe.Ciphertext) (FVPasta2NoiseTrace, error) {
	_ = layer
	_ = round
	if e == nil || e.runtime == nil {
		return FVPasta2NoiseTrace{}, fmt.Errorf("BGV residual noise estimator requires a runtime")
	}
	if len(state) == 0 {
		return FVPasta2NoiseTrace{}, nil
	}

	trace := FVPasta2NoiseTrace{}
	for i, ciphertext := range state {
		values, err := e.runtime.DecryptUint(ciphertext)
		if err != nil {
			return FVPasta2NoiseTrace{}, fmt.Errorf("decrypt coordinate %d: %w", i, err)
		}
		plaintext := bgv.NewPlaintext(e.runtime.params, ciphertext.Level())
		if ciphertext.MetaData != nil {
			plaintext.MetaData = ciphertext.MetaData.CopyNew()
		}
		if err := e.runtime.encoder.Encode(values, plaintext); err != nil {
			return FVPasta2NoiseTrace{}, fmt.Errorf("encode recovered coordinate %d: %w", i, err)
		}
		residual, err := e.runtime.evaluator.SubNew(ciphertext, plaintext)
		if err != nil {
			return FVPasta2NoiseTrace{}, fmt.Errorf("subtract recovered plaintext coordinate %d: %w", i, err)
		}
		std, minAbs, maxAbs := rlwe.Norm(residual, e.runtime.decryptor)
		if i == 0 {
			trace.MinStdLog2 = std
			trace.MaxStdLog2 = std
			trace.MinAbsMinLog2 = minAbs
			trace.MaxAbsMinLog2 = minAbs
			trace.MinAbsMaxLog2 = maxAbs
			trace.MaxAbsMaxLog2 = maxAbs
			continue
		}
		if std < trace.MinStdLog2 {
			trace.MinStdLog2 = std
		}
		if std > trace.MaxStdLog2 {
			trace.MaxStdLog2 = std
		}
		if minAbs < trace.MinAbsMinLog2 {
			trace.MinAbsMinLog2 = minAbs
		}
		if minAbs > trace.MaxAbsMinLog2 {
			trace.MaxAbsMinLog2 = minAbs
		}
		if maxAbs < trace.MinAbsMaxLog2 {
			trace.MinAbsMaxLog2 = maxAbs
		}
		if maxAbs > trace.MaxAbsMaxLog2 {
			trace.MaxAbsMaxLog2 = maxAbs
		}
	}
	return trace, nil
}

// FVPasta2LayerTrace records ciphertext metadata after a Pasta2 nonlinear layer.
type FVPasta2LayerTrace struct {
	Layer       string
	Round       int
	Coordinates int
	MinLevel    int
	MaxLevel    int
	MinDegree   int
	MaxDegree   int
	MinLogScale float64
	MaxLogScale float64
	Noise       *FVPasta2NoiseTrace
}

// String returns a human-readable representation of the noise trace.
func (n FVPasta2NoiseTrace) String() string {
	return fmt.Sprintf("NoiseTrace(StdDev: [%.2f, %.2f], AbsMin: [%.2f, %.2f], AbsMax: [%.2f, %.2f])",
		n.MinStdLog2, n.MaxStdLog2, n.MinAbsMinLog2, n.MaxAbsMinLog2, n.MinAbsMaxLog2, n.MaxAbsMaxLog2)
}

// String returns a human-readable representation of the layer trace.
func (t FVPasta2LayerTrace) String() string {
	noiseStr := "<nil>"
	if t.Noise != nil {
		noiseStr = t.Noise.String()
	}
	return fmt.Sprintf("LayerTrace{Layer: %s, Round: %d, Coordinates: %d, Level: [%d, %d], Degree: [%d, %d], LogScale: [%.2f, %.2f], Noise: %s}",
		t.Layer, t.Round, t.Coordinates, t.MinLevel, t.MaxLevel, t.MinDegree, t.MaxDegree, t.MinLogScale, t.MaxLogScale, noiseStr)
}

// Print prints a human-readable summary of the layer trace to standard output.
func (t FVPasta2LayerTrace) Print() {
	fmt.Printf("--- FVPasta2 Layer Trace Info ---\n")
	fmt.Printf("Layer:       %s\n", t.Layer)
	fmt.Printf("Round:       %d\n", t.Round)
	fmt.Printf("Coordinates: %d\n", t.Coordinates)
	fmt.Printf("Level:       [%d, %d]\n", t.MinLevel, t.MaxLevel)
	fmt.Printf("Degree:      [%d, %d]\n", t.MinDegree, t.MaxDegree)
	fmt.Printf("LogScale:    [%.2f, %.2f]\n", t.MinLogScale, t.MaxLogScale)
	if t.Noise != nil {
		fmt.Printf("Noise (log2):\n")
		fmt.Printf("  Std Dev:   [%.2f, %.2f]\n", t.Noise.MinStdLog2, t.Noise.MaxStdLog2)
		fmt.Printf("  Abs Min:   [%.2f, %.2f]\n", t.Noise.MinAbsMinLog2, t.Noise.MaxAbsMinLog2)
		fmt.Printf("  Abs Max:   [%.2f, %.2f]\n", t.Noise.MinAbsMaxLog2, t.Noise.MaxAbsMaxLog2)
	} else {
		fmt.Printf("Noise:       <nil>\n")
	}
	fmt.Printf("---------------------------------\n")
}

// NewFVPasta2Evaluator constructs an FV evaluator for Pasta v2 with serial execution.
// The BGV plaintext modulus must match params.Modulus.
func NewFVPasta2Evaluator(runtime *BGVRuntime, params sympasta2.Parameter) (*FVPasta2Evaluator, error) {
	return NewFVPasta2EvaluatorWithConfig(runtime, params, SerialConfig())
}

// NewFVPasta2EvaluatorWithConfig constructs an FV evaluator for Pasta v2 with the given parallel config.
// The BGV plaintext modulus must match params.Modulus.
func NewFVPasta2EvaluatorWithConfig(runtime *BGVRuntime, params sympasta2.Parameter, cfg ParallelConfig) (*FVPasta2Evaluator, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if runtime.Parameters().PlaintextModulus() != params.GetModulus() {
		return nil, fmt.Errorf("BGV plaintext modulus %d does not match Pasta2 modulus %d", runtime.Parameters().PlaintextModulus(), params.GetModulus())
	}

	fullStateSize := params.GetKeySize()
	if fullStateSize <= 0 {
		return nil, fmt.Errorf("invalid Pasta2 full state size %d", fullStateSize)
	}
	if params.GetBlockSize() <= 0 || params.GetBlockSize() > fullStateSize {
		return nil, fmt.Errorf("invalid Pasta2 output size %d for full state size %d", params.GetBlockSize(), fullStateSize)
	}
	base, err := newBaseCipher(runtime, fullStateSize, params.GetBlockSize(), cfg)
	if err != nil {
		return nil, err
	}

	inst, err := sympasta2.NewInstance(params)
	if err != nil {
		return nil, err
	}

	return &FVPasta2Evaluator{
		base:   base,
		params: params,
		p:      params.GetModulus(),
		inst:   inst,
		mask:   pasta2FieldMask(params.GetModulus()),
		cfg:    cfg,
	}, nil
}

func (p *FVPasta2Evaluator) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	if len(key) != p.params.GetKeySize() {
		return nil, fmt.Errorf("invalid key length %d, expected %d", len(key), p.params.GetKeySize())
	}
	for i, value := range key {
		if value >= p.p {
			return nil, fmt.Errorf("invalid key word at index %d: got %d, want < %d", i, value, p.p)
		}
	}
	return p.base.EncryptKey(key)
}

func (p *FVPasta2Evaluator) SetNoiseEstimator(estimator FVPasta2NoiseEstimator) {
	p.noiseEstimator = estimator
}

// Crypt evaluates the Pasta v2 keystream left branch for each nonce/counter lane.
func (p *FVPasta2Evaluator) Crypt(nonces [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	return p.crypt(nonces, encryptedKey, nil)
}

// CryptWithTrace evaluates the Pasta v2 keystream and records metadata after each nonlinear layer.
func (p *FVPasta2Evaluator) CryptWithTrace(nonces [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, []FVPasta2LayerTrace, error) {
	trace := make([]FVPasta2LayerTrace, 0, p.params.GetRounds())
	keystream, err := p.crypt(nonces, encryptedKey, &trace)
	if err != nil {
		return nil, nil, err
	}
	return keystream, trace, nil
}

func (p *FVPasta2Evaluator) crypt(nonces [][]byte, encryptedKey []*rlwe.Ciphertext, trace *[]FVPasta2LayerTrace) ([]*rlwe.Ciphertext, error) {
	if err := p.validateCryptInputs(nonces, encryptedKey); err != nil {
		return nil, err
	}

	state := cloneCiphertexts(encryptedKey)

	var err error
	state, err = p.affine0(nonces, state)
	if err != nil {
		return nil, err
	}

	for q := 0; q < p.params.GetRounds()-1; q++ {
		state, err = p.feistelBranches(state)
		if err != nil {
			return nil, err
		}
		if err := p.appendLayerTrace(trace, "S_feistel", q+1, state); err != nil {
			return nil, err
		}
		state, err = p.affineFixed(q, state)
		if err != nil {
			return nil, err
		}
	}

	state, err = cubeState(p.base.runtime.evaluator, state, p.cfg)
	if err != nil {
		return nil, err
	}
	if err := p.appendLayerTrace(trace, "S_cube", p.params.GetRounds(), state); err != nil {
		return nil, err
	}
	state, err = p.affineFixed(p.params.GetRounds()-1, state)
	if err != nil {
		return nil, err
	}

	return append([]*rlwe.Ciphertext(nil), state[:p.params.GetBlockSize()]...), nil
}

func (p *FVPasta2Evaluator) validateCryptInputs(nonces [][]byte, encryptedKey []*rlwe.Ciphertext) error {
	if len(nonces) > p.base.runtime.Slots() {
		return fmt.Errorf("too many lanes: got %d, max %d", len(nonces), p.base.runtime.Slots())
	}
	for lane, nonce := range nonces {
		if len(nonce) != 2*sym.NonceSize {
			return fmt.Errorf("invalid Pasta2 nonce/counter seed length at lane %d: got %d, want %d", lane, len(nonce), 2*sym.NonceSize)
		}
	}
	if len(encryptedKey) != p.params.GetKeySize() {
		return fmt.Errorf("invalid encrypted key length %d, expected %d", len(encryptedKey), p.params.GetKeySize())
	}
	return nil
}

// DecryptSymmetricBlocks computes symCt - Pasta2Keystream under FV.
func (p *FVPasta2Evaluator) DecryptSymmetricBlocks(nonces [][]byte, encryptedKey []*rlwe.Ciphertext, symCt [][]uint64) ([]*rlwe.Ciphertext, error) {
	if len(symCt) != len(nonces) {
		return nil, fmt.Errorf("invalid symmetric ciphertext lane count %d, expected %d", len(symCt), len(nonces))
	}
	t := p.params.GetBlockSize()
	for lane, block := range symCt {
		if len(block) > t {
			return nil, fmt.Errorf("invalid symmetric ciphertext block length at lane %d: got %d, max %d", lane, len(block), t)
		}
		for j, value := range block {
			if value >= p.p {
				return nil, fmt.Errorf("invalid symmetric ciphertext word lane %d index %d: got %d, want < %d", lane, j, value, p.p)
			}
		}
	}

	keystream, err := p.Crypt(nonces, encryptedKey)
	if err != nil {
		return nil, err
	}

	pts := make([]*rlwe.Plaintext, t)
	for j := 0; j < t; j++ {
		values := make([]uint64, len(nonces))
		for lane := range nonces {
			if j < len(symCt[lane]) {
				values[lane] = symCt[lane][j]
			}
		}
		plaintext, err := p.base.runtime.encodeUint(padUint(values, p.base.runtime.Slots()))
		if err != nil {
			return nil, err
		}
		pts[j] = plaintext
	}

	out := make([]*rlwe.Ciphertext, t)
	err = parallelDo(t, p.cfg.MaxWorkers, p.cfg.Guard, func(j int) error {
		localEval := p.base.runtime.evaluator.ShallowCopy()
		negated, err := multiplyByScalar(localEval, keystream[j], p.p-1)
		if err != nil {
			return fmt.Errorf("negate keystream coordinate %d: %w", j, err)
		}
		if err := localEval.Add(negated, pts[j], negated); err != nil {
			return fmt.Errorf("add symmetric ciphertext coordinate %d: %w", j, err)
		}
		out[j] = negated
		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (p *FVPasta2Evaluator) affine0(nonces [][]byte, state []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	t := p.params.GetBlockSize()
	left := state[:t]
	right := state[t:]
	c0L, c0R, betaL, betaR, err := p.blockMasks(nonces)
	if err != nil {
		return nil, err
	}

	switch p.params.GetMode() {
	case sympasta2.ModeSpecStrict:
		maskedL, err := p.multiplyByPlainVec(left, betaL)
		if err != nil {
			return nil, err
		}
		maskedR, err := p.multiplyByPlainVec(right, betaR)
		if err != nil {
			return nil, err
		}
		zL, err := p.matVec(p.inst.MfL, maskedL)
		if err != nil {
			return nil, err
		}
		zR, err := p.matVec(p.inst.MfR, maskedR)
		if err != nil {
			return nil, err
		}
		if err := p.addPlainVec(zL, c0L); err != nil {
			return nil, err
		}
		if err := p.addPlainVec(zR, c0R); err != nil {
			return nil, err
		}
		return p.mix(zL, zR)

	case sympasta2.ModeCompatCPP:
		zL, err := p.matVec(p.inst.MfL, left)
		if err != nil {
			return nil, err
		}
		zR, err := p.matVec(p.inst.MfR, right)
		if err != nil {
			return nil, err
		}
		if err := p.multiplyByPlainVecInPlace(zL, betaL); err != nil {
			return nil, err
		}
		if err := p.multiplyByPlainVecInPlace(zR, betaR); err != nil {
			return nil, err
		}
		if err := p.addPlainVec(zL, c0L); err != nil {
			return nil, err
		}
		if err := p.addPlainVec(zR, c0R); err != nil {
			return nil, err
		}
		return p.mix(zL, zR)

	default:
		return nil, fmt.Errorf("invalid Pasta2 mode %d", p.params.GetMode())
	}
}

func (p *FVPasta2Evaluator) affineFixed(q int, state []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	t := p.params.GetBlockSize()
	zL, err := p.matVec(p.inst.M, state[:t])
	if err != nil {
		return nil, err
	}
	zR, err := p.matVec(p.inst.M, state[t:])
	if err != nil {
		return nil, err
	}
	if err := p.addConstVec(zL, p.inst.RcL[q]); err != nil {
		return nil, err
	}
	if err := p.addConstVec(zR, p.inst.RcR[q]); err != nil {
		return nil, err
	}
	return p.mix(zL, zR)
}

func (p *FVPasta2Evaluator) feistelBranches(state []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	t := p.params.GetBlockSize()
	left, err := feistelState(p.base.runtime.evaluator, state[:t], p.cfg)
	if err != nil {
		return nil, err
	}
	right, err := feistelState(p.base.runtime.evaluator, state[t:], p.cfg)
	if err != nil {
		return nil, err
	}
	out := make([]*rlwe.Ciphertext, 0, len(state))
	out = append(out, left...)
	out = append(out, right...)
	return out, nil
}

func (p *FVPasta2Evaluator) matVec(matrix sym.Matrix, branch []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	if len(matrix) != len(branch) {
		return nil, fmt.Errorf("matrix row count %d does not match branch length %d", len(matrix), len(branch))
	}

	out := make([]*rlwe.Ciphertext, len(branch))
	err := parallelDo(len(branch), p.cfg.MaxWorkers, p.cfg.Guard, func(i int) error {
		row := matrix[i]
		if len(row) != len(branch) {
			return fmt.Errorf("matrix row %d length %d does not match branch length %d", i, len(row), len(branch))
		}
		terms := make([]weightedCiphertext, 0, len(row))
		for j, coeff := range row {
			if coeff == 0 {
				continue
			}
			terms = append(terms, weightedCiphertext{coeff: coeff, ct: branch[j]})
		}
		if len(terms) == 0 {
			return fmt.Errorf("matrix row %d has no nonzero coefficients", i)
		}
		localEval := p.base.runtime.evaluator.ShallowCopy()
		combined, err := linearCombination(localEval, terms)
		if err != nil {
			return fmt.Errorf("matrix row %d: %w", i, err)
		}
		out[i] = combined
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *FVPasta2Evaluator) multiplyByPlainVec(state []*rlwe.Ciphertext, masks [][]uint64) ([]*rlwe.Ciphertext, error) {
	out := cloneCiphertexts(state)
	if err := p.multiplyByPlainVecInPlace(out, masks); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *FVPasta2Evaluator) multiplyByPlainVecInPlace(state []*rlwe.Ciphertext, masks [][]uint64) error {
	if len(masks) != len(state) {
		return fmt.Errorf("mask length %d does not match state length %d", len(masks), len(state))
	}
	pts := make([]*rlwe.Plaintext, len(state))
	for i := range state {
		pt, err := p.base.runtime.encodeUint(padUint(masks[i], p.base.runtime.Slots()))
		if err != nil {
			return err
		}
		pts[i] = pt
	}

	return parallelDo(len(state), p.cfg.MaxWorkers, p.cfg.Guard, func(i int) error {
		localEval := p.base.runtime.evaluator.ShallowCopy()
		if err := localEval.Mul(state[i], pts[i], state[i]); err != nil {
			return fmt.Errorf("multiply state coordinate %d by plaintext vector: %w", i, err)
		}
		return nil
	})
}

func (p *FVPasta2Evaluator) addPlainVec(state []*rlwe.Ciphertext, values [][]uint64) error {
	if len(values) != len(state) {
		return fmt.Errorf("value length %d does not match state length %d", len(values), len(state))
	}
	pts := make([]*rlwe.Plaintext, len(state))
	for i := range state {
		pt, err := p.base.runtime.encodeUint(padUint(values[i], p.base.runtime.Slots()))
		if err != nil {
			return err
		}
		pts[i] = pt
	}

	return parallelDo(len(state), p.cfg.MaxWorkers, p.cfg.Guard, func(i int) error {
		localEval := p.base.runtime.evaluator.ShallowCopy()
		if err := localEval.Add(state[i], pts[i], state[i]); err != nil {
			return fmt.Errorf("add plaintext vector to coordinate %d: %w", i, err)
		}
		return nil
	})
}

func (p *FVPasta2Evaluator) addConstVec(state []*rlwe.Ciphertext, values []uint64) error {
	if len(values) != len(state) {
		return fmt.Errorf("constant length %d does not match state length %d", len(values), len(state))
	}
	pts := make([]*rlwe.Plaintext, len(state))
	for i, value := range values {
		if value == 0 {
			continue
		}
		pt, err := p.base.runtime.encodeUint(repeatUint(value, p.base.runtime.Slots()))
		if err != nil {
			return err
		}
		pts[i] = pt
	}

	return parallelDo(len(state), p.cfg.MaxWorkers, p.cfg.Guard, func(i int) error {
		if pts[i] == nil {
			return nil
		}
		localEval := p.base.runtime.evaluator.ShallowCopy()
		if err := localEval.Add(state[i], pts[i], state[i]); err != nil {
			return fmt.Errorf("add constant to coordinate %d: %w", i, err)
		}
		return nil
	})
}

func (p *FVPasta2Evaluator) mix(zL, zR []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	if len(zL) != len(zR) {
		return nil, fmt.Errorf("branch length mismatch: %d != %d", len(zL), len(zR))
	}

	state := make([]*rlwe.Ciphertext, 2*len(zL))
	err := parallelDo(len(zL), p.cfg.MaxWorkers, p.cfg.Guard, func(i int) error {
		localEval := p.base.runtime.evaluator.ShallowCopy()
		sum, err := localEval.AddNew(zL[i], zR[i])
		if err != nil {
			return fmt.Errorf("mix sum coordinate %d: %w", i, err)
		}
		left, err := localEval.AddNew(zL[i], sum)
		if err != nil {
			return fmt.Errorf("mix left coordinate %d: %w", i, err)
		}
		right, err := localEval.AddNew(zR[i], sum)
		if err != nil {
			return fmt.Errorf("mix right coordinate %d: %w", i, err)
		}
		state[i] = left
		state[len(zL)+i] = right
		return nil
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (p *FVPasta2Evaluator) blockMasks(nonces [][]byte) (c0L, c0R, betaL, betaR [][]uint64, err error) {
	t := p.params.GetBlockSize()
	c0L = makeLaneMatrix(t, len(nonces))
	c0R = makeLaneMatrix(t, len(nonces))
	betaL = makeLaneMatrix(t, len(nonces))
	betaR = makeLaneMatrix(t, len(nonces))

	for lane, nonce := range nonces {
		shake := sha3.NewShake128()
		if _, err := shake.Write(nonce); err != nil {
			return nil, nil, nil, nil, err
		}

		switch p.params.GetMode() {
		case sympasta2.ModeSpecStrict:
			p.sampleLaneVec(shake, c0L, lane, true)
			p.sampleLaneVec(shake, c0R, lane, true)
			p.sampleLaneVec(shake, betaL, lane, false)
			p.sampleLaneVec(shake, betaR, lane, false)
		case sympasta2.ModeCompatCPP:
			p.sampleLaneVec(shake, betaL, lane, false)
			p.sampleLaneVec(shake, betaR, lane, false)
			p.sampleLaneVec(shake, c0L, lane, true)
			p.sampleLaneVec(shake, c0R, lane, true)
		default:
			return nil, nil, nil, nil, fmt.Errorf("invalid Pasta2 mode %d", p.params.GetMode())
		}
	}

	return c0L, c0R, betaL, betaR, nil
}

func (p *FVPasta2Evaluator) sampleLaneVec(shake sha3.ShakeHash, values [][]uint64, lane int, allowZero bool) {
	for i := range values {
		values[i][lane] = p.sampleFrom(shake, allowZero)
	}
}

func (p *FVPasta2Evaluator) sampleFrom(shake sha3.ShakeHash, allowZero bool) uint64 {
	var buf [8]byte
	for {
		if _, err := shake.Read(buf[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}
		x := binary.BigEndian.Uint64(buf[:]) & p.mask
		if x >= p.p {
			continue
		}
		if !allowZero && x == 0 {
			continue
		}
		return x
	}
}

func (p *FVPasta2Evaluator) appendLayerTrace(trace *[]FVPasta2LayerTrace, layer string, round int, state []*rlwe.Ciphertext) error {
	if trace == nil {
		return nil
	}
	record := newPasta2LayerTrace(layer, round, state)
	if p.noiseEstimator != nil {
		noise, err := p.noiseEstimator.EstimatePasta2Noise(layer, round, state)
		if err != nil {
			return fmt.Errorf("estimate Pasta2 noise after %s round %d: %w", layer, round, err)
		}
		record.Noise = &noise
	}
	*trace = append(*trace, record)
	return nil
}

func newPasta2LayerTrace(layer string, round int, state []*rlwe.Ciphertext) FVPasta2LayerTrace {
	record := FVPasta2LayerTrace{Layer: layer, Round: round, Coordinates: len(state)}
	if len(state) == 0 {
		return record
	}

	first := state[0]
	record.MinLevel = first.Level()
	record.MaxLevel = first.Level()
	record.MinDegree = first.Degree()
	record.MaxDegree = first.Degree()
	record.MinLogScale = first.LogScale()
	record.MaxLogScale = first.LogScale()
	for _, ciphertext := range state[1:] {
		level := ciphertext.Level()
		if level < record.MinLevel {
			record.MinLevel = level
		}
		if level > record.MaxLevel {
			record.MaxLevel = level
		}

		degree := ciphertext.Degree()
		if degree < record.MinDegree {
			record.MinDegree = degree
		}
		if degree > record.MaxDegree {
			record.MaxDegree = degree
		}

		logScale := ciphertext.LogScale()
		if logScale < record.MinLogScale {
			record.MinLogScale = logScale
		}
		if logScale > record.MaxLogScale {
			record.MaxLogScale = logScale
		}
	}
	return record
}

func makeLaneMatrix(rows, lanes int) [][]uint64 {
	values := make([][]uint64, rows)
	for i := range values {
		values[i] = make([]uint64, lanes)
	}
	return values
}

func pasta2FieldMask(p uint64) uint64 {
	bitLen := bits.Len64(p)
	if bitLen == 64 {
		return ^uint64(0)
	}
	return uint64(1<<bitLen) - 1
}
