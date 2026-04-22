package internal

import (
	"fmt"

	symrubato "github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/hosseinabdinf/sherdal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

// FVRubatoEvaluator keeps the modular keystream generation isolated from the RtF bridge.
type FVRubatoEvaluator struct {
	base   *baseCipher
	params symrubato.Parameter
	width  int
	coeffs []uint64
}

func NewFVRubatoEvaluator(runtime *BGVRuntime, params symrubato.Parameter) (*FVRubatoEvaluator, error) {
	width, coeffs, err := rubatoLayout(params.BlockSize)
	if err != nil {
		return nil, err
	}

	base, err := newBaseCipher(runtime, params.BlockSize, params.BlockSize-4)
	if err != nil {
		return nil, err
	}

	return &FVRubatoEvaluator{base: base, params: params, width: width, coeffs: coeffs}, nil
}

func (r *FVRubatoEvaluator) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	return r.base.EncryptKey(key)
}

func (r *FVRubatoEvaluator) Crypt(nonces [][]byte, counter []byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	counters := make([][]byte, len(nonces))
	for i := range counters {
		counters[i] = counter
	}
	return r.CryptWithCounters(nonces, counters, encryptedKey)
}

func (r *FVRubatoEvaluator) CryptWithCounters(nonces [][]byte, counters [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	roundConstants := r.roundConstants(nonces, counters)
	state := r.base.initialState()

	if err := r.base.addRoundKey(state, encryptedKey, roundConstants[0]); err != nil {
		return nil, err
	}

	for round := 1; round < r.params.Rounds; round++ {
		mixed, err := applyCirculantLayer(r.base.runtime.evaluator, state, r.width, r.coeffs)
		if err != nil {
			return nil, err
		}

		feistel, err := feistelState(r.base.runtime.evaluator, mixed)
		if err != nil {
			return nil, err
		}

		state = feistel
		if err := r.base.addRoundKey(state, encryptedKey, roundConstants[round]); err != nil {
			return nil, err
		}
	}

	mixed, err := applyCirculantLayer(r.base.runtime.evaluator, state, r.width, r.coeffs)
	if err != nil {
		return nil, err
	}

	feistel, err := feistelState(r.base.runtime.evaluator, mixed)
	if err != nil {
		return nil, err
	}

	state, err = applyCirculantLayer(r.base.runtime.evaluator, feistel, r.width, r.coeffs)
	if err != nil {
		return nil, err
	}

	if err := r.base.addRoundKey(state, encryptedKey, roundConstants[r.params.Rounds]); err != nil {
		return nil, err
	}

	return append([]*rlwe.Ciphertext(nil), state[:r.base.outputSize]...), nil
}

func (r *FVRubatoEvaluator) roundConstants(nonces [][]byte, counters [][]byte) [][][]uint64 {
	rounds := r.params.Rounds + 1
	constants := make([][][]uint64, rounds)
	for round := 0; round < rounds; round++ {
		constants[round] = make([][]uint64, r.base.blockSize)
		for state := 0; state < r.base.blockSize; state++ {
			constants[round][state] = make([]uint64, len(nonces))
		}
	}

	for lane, nonce := range nonces {
		shake := sha3.NewShake256()
		_, _ = shake.Write(nonce)
		if lane < len(counters) && counters[lane] != nil {
			_, _ = shake.Write(counters[lane])
		}

		for round := 0; round < rounds; round++ {
			for state := 0; state < r.base.blockSize; state++ {
				constants[round][state][lane] = utils.RubSampleZqx(shake, r.params.Modulus)
			}
		}
	}

	return constants
}

func rubatoLayout(blockSize int) (width int, coeffs []uint64, err error) {
	switch blockSize {
	case 16:
		return 4, []uint64{2, 3, 1, 1}, nil
	case 36:
		return 6, []uint64{4, 2, 4, 3, 1, 1}, nil
	case 64:
		return 8, []uint64{5, 3, 4, 3, 6, 2, 1, 1}, nil
	default:
		return 0, nil, fmt.Errorf("unsupported Rubato block size %d", blockSize)
	}
}
