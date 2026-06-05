package pkg

import (
	"fmt"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"

	"github.com/hosseinabdinf/sherdal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

// heraMixCoefficients represents the circulant mixing matrix coefficients used in the linear layer.
var heraMixCoefficients = []uint64{2, 3, 1, 1}

// FVHeraEvaluator evaluates the modular HERA keystream over BGV.
type FVHeraEvaluator struct {
	base   *baseCipher
	params symhera.Parameter
	cfg    ParallelConfig
}

// NewFVHeraEvaluator creates and initializes a new FVHeraEvaluator with serial execution.
// It currently only supports a HERA block size of 16. Returns an error if
// the block size is unsupported or if base cipher initialization fails.
func NewFVHeraEvaluator(runtime *BGVRuntime, params symhera.Parameter) (*FVHeraEvaluator, error) {
	return NewFVHeraEvaluatorWithConfig(runtime, params, SerialConfig())
}

// NewFVHeraEvaluatorWithConfig creates a new FVHeraEvaluator with the given parallel config.
// It currently only supports a HERA block size of 16.
func NewFVHeraEvaluatorWithConfig(runtime *BGVRuntime, params symhera.Parameter, cfg ParallelConfig) (*FVHeraEvaluator, error) {
	if params.BlockSize != 16 {
		return nil, fmt.Errorf("unsupported HERA block size %d", params.BlockSize)
	}

	base, err := newBaseCipher(runtime, params.BlockSize, params.BlockSize, cfg)
	if err != nil {
		return nil, err
	}

	return &FVHeraEvaluator{base: base, params: params, cfg: cfg}, nil
}

// EncryptKey encrypts each element of the symmetric key using the BGV runtime.
// It returns a slice of ciphertexts representing the encrypted key, or an error if encryption fails.
func (h *FVHeraEvaluator) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	return h.base.EncryptKey(key)
}

// Crypt homomorphically evaluates the modular HERA keystream generation pipeline over BGV ciphertexts.
// It takes a list of nonces (one per slot lane) and the encrypted key ciphertexts, and returns the
// generated keystream ciphertexts. The evaluation consists of state initialization, non-linear S-box
// layers (cubing), linear layers (circulant mixing matrix application), and round key additions using
// pseudorandom round constants generated from the input nonces.
func (h *FVHeraEvaluator) Crypt(nonces [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	roundConstants := h.roundConstants(nonces)
	state := h.base.initialState()
	eval := h.base.runtime.evaluator

	if err := h.base.addRoundKey(state, encryptedKey, roundConstants[0]); err != nil {
		return nil, err
	}

	for round := 1; round < h.params.Rounds; round++ {
		mixed, err := applyCirculantLayer(eval, state, 4, heraMixCoefficients, h.cfg)
		if err != nil {
			return nil, err
		}

		cubed, err := cubeState(eval, mixed, h.cfg)
		if err != nil {
			return nil, err
		}

		state = cubed
		if err := h.base.addRoundKey(state, encryptedKey, roundConstants[round]); err != nil {
			return nil, err
		}
	}

	mixed, err := applyCirculantLayer(eval, state, 4, heraMixCoefficients, h.cfg)
	if err != nil {
		return nil, err
	}

	cubed, err := cubeState(eval, mixed, h.cfg)
	if err != nil {
		return nil, err
	}

	state, err = applyCirculantLayer(eval, cubed, 4, heraMixCoefficients, h.cfg)
	if err != nil {
		return nil, err
	}

	if err := h.base.addRoundKey(state, encryptedKey, roundConstants[h.params.Rounds]); err != nil {
		return nil, err
	}

	return state, nil
}

// roundConstants generates the pseudorandom round constants for the HERA evaluation rounds.
// It initializes a Shake256 PRNG for each lane (nonce) and samples round constant values
// within the configured HERA modulus.
//
// Each lane owns its own independent SHAKE256 stream and writes to disjoint positions
// in the constants tensor (constants[round][state][lane]), so all lanes run in parallel.
func (h *FVHeraEvaluator) roundConstants(nonces [][]byte) [][][]uint64 {
	rounds := h.params.Rounds + 1
	constants := make([][][]uint64, rounds)
	for round := 0; round < rounds; round++ {
		constants[round] = make([][]uint64, h.base.blockSize)
		for state := 0; state < h.base.blockSize; state++ {
			constants[round][state] = make([]uint64, len(nonces))
		}
	}

	// Parallelise over lanes: each goroutine writes only to constants[*][*][lane].
	_ = parallelDo(len(nonces), h.cfg.MaxWorkers, h.cfg.Guard, func(lane int) error {
		shake := sha3.NewShake256()
		_, _ = shake.Write(nonces[lane])
		for round := 0; round < rounds; round++ {
			for state := 0; state < h.base.blockSize; state++ {
				constants[round][state][lane] = utils.SampleZq(shake, h.params.Modulus)
			}
		}
		return nil
	})

	return constants
}
