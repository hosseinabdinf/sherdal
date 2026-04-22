package internal

import (
	"fmt"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"

	"github.com/hosseinabdinf/sherdal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

var heraMixCoefficients = []uint64{2, 3, 1, 1}

// FVHeraEvaluator evaluates the modular HERA keystream over BGV.
type FVHeraEvaluator struct {
	base   *baseCipher
	params symhera.Parameter
}

func NewFVHeraEvaluator(runtime *BGVRuntime, params symhera.Parameter) (*FVHeraEvaluator, error) {
	if params.BlockSize != 16 {
		return nil, fmt.Errorf("unsupported HERA block size %d", params.BlockSize)
	}

	base, err := newBaseCipher(runtime, params.BlockSize, params.BlockSize)
	if err != nil {
		return nil, err
	}

	return &FVHeraEvaluator{base: base, params: params}, nil
}

func (h *FVHeraEvaluator) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	return h.base.EncryptKey(key)
}

func (h *FVHeraEvaluator) Crypt(nonces [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	roundConstants := h.roundConstants(nonces)
	state := h.base.initialState()

	if err := h.base.addRoundKey(state, encryptedKey, roundConstants[0]); err != nil {
		return nil, err
	}

	for round := 1; round < h.params.Rounds; round++ {
		mixed, err := applyCirculantLayer(h.base.runtime.evaluator, state, 4, heraMixCoefficients)
		if err != nil {
			return nil, err
		}

		cubed, err := cubeState(h.base.runtime.evaluator, mixed)
		if err != nil {
			return nil, err
		}

		state = cubed
		if err := h.base.addRoundKey(state, encryptedKey, roundConstants[round]); err != nil {
			return nil, err
		}
	}

	mixed, err := applyCirculantLayer(h.base.runtime.evaluator, state, 4, heraMixCoefficients)
	if err != nil {
		return nil, err
	}

	cubed, err := cubeState(h.base.runtime.evaluator, mixed)
	if err != nil {
		return nil, err
	}

	state, err = applyCirculantLayer(h.base.runtime.evaluator, cubed, 4, heraMixCoefficients)
	if err != nil {
		return nil, err
	}

	if err := h.base.addRoundKey(state, encryptedKey, roundConstants[h.params.Rounds]); err != nil {
		return nil, err
	}

	return state, nil
}

func (h *FVHeraEvaluator) roundConstants(nonces [][]byte) [][][]uint64 {
	rounds := h.params.Rounds + 1
	constants := make([][][]uint64, rounds)
	for round := 0; round < rounds; round++ {
		constants[round] = make([][]uint64, h.base.blockSize)
		for state := 0; state < h.base.blockSize; state++ {
			constants[round][state] = make([]uint64, len(nonces))
		}
	}

	for lane, nonce := range nonces {
		shake := sha3.NewShake256()
		_, _ = shake.Write(nonce)

		for round := 0; round < rounds; round++ {
			for state := 0; state < h.base.blockSize; state++ {
				constants[round][state][lane] = utils.SampleZq(shake, h.params.Modulus)
			}
		}
	}

	return constants
}
