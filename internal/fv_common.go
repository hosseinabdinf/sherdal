package internal

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type baseCipher struct {
	runtime       *BGVRuntime
	blockSize     int
	outputSize    int
	stateTemplate []*rlwe.Ciphertext
}

type weightedCiphertext struct {
	coeff uint64
	ct    *rlwe.Ciphertext
}

func newBaseCipher(runtime *BGVRuntime, blockSize, outputSize int) (*baseCipher, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size %d", blockSize)
	}
	if outputSize <= 0 || outputSize > blockSize {
		return nil, fmt.Errorf("invalid output size %d", outputSize)
	}

	stateTemplate := make([]*rlwe.Ciphertext, blockSize)
	for i := 0; i < blockSize; i++ {
		ciphertext, err := runtime.encryptUint(repeatUint(uint64(i+1), runtime.Slots()))
		if err != nil {
			return nil, err
		}
		stateTemplate[i] = ciphertext
	}

	return &baseCipher{
		runtime:       runtime,
		blockSize:     blockSize,
		outputSize:    outputSize,
		stateTemplate: stateTemplate,
	}, nil
}

func (b *baseCipher) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	if len(key) != b.blockSize {
		return nil, fmt.Errorf("invalid key length %d, expected %d", len(key), b.blockSize)
	}

	encryptedKey := make([]*rlwe.Ciphertext, b.blockSize)
	for i, value := range key {
		ciphertext, err := b.runtime.encryptUint(repeatUint(value, b.runtime.Slots()))
		if err != nil {
			return nil, err
		}
		encryptedKey[i] = ciphertext
	}

	return encryptedKey, nil
}

func (b *baseCipher) initialState() []*rlwe.Ciphertext {
	return cloneCiphertexts(b.stateTemplate)
}

func (b *baseCipher) addRoundKey(state, encryptedKey []*rlwe.Ciphertext, roundConstants [][]uint64) error {
	if len(state) != b.blockSize {
		return fmt.Errorf("invalid state length %d, expected %d", len(state), b.blockSize)
	}
	if len(encryptedKey) != b.blockSize {
		return fmt.Errorf("invalid encrypted key length %d, expected %d", len(encryptedKey), b.blockSize)
	}
	if len(roundConstants) != b.blockSize {
		return fmt.Errorf("invalid round constant length %d, expected %d", len(roundConstants), b.blockSize)
	}

	for i := 0; i < b.blockSize; i++ {
		plaintext, err := b.runtime.encodeUint(padUint(roundConstants[i], b.runtime.Slots()))
		if err != nil {
			return err
		}

		roundKey := encryptedKey[i].CopyNew()
		if err := b.runtime.evaluator.Mul(roundKey, plaintext, roundKey); err != nil {
			return fmt.Errorf("multiply round key %d: %w", i, err)
		}
		if err := b.runtime.evaluator.Add(state[i], roundKey, state[i]); err != nil {
			return fmt.Errorf("add round key %d: %w", i, err)
		}
	}

	return nil
}

func cloneCiphertexts(ciphertexts []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	clones := make([]*rlwe.Ciphertext, len(ciphertexts))
	for i, ciphertext := range ciphertexts {
		clones[i] = ciphertext.CopyNew()
	}
	return clones
}

func linearCombination(eval *bgv.Evaluator, terms []weightedCiphertext) (*rlwe.Ciphertext, error) {
	if len(terms) == 0 {
		return nil, fmt.Errorf("linear combination requires at least one term")
	}

	acc, err := multiplyByScalar(eval, terms[0].ct, terms[0].coeff)
	if err != nil {
		return nil, err
	}

	for _, term := range terms[1:] {
		tmp, err := multiplyByScalar(eval, term.ct, term.coeff)
		if err != nil {
			return nil, err
		}
		if err := eval.Add(acc, tmp, acc); err != nil {
			return nil, fmt.Errorf("add linear term: %w", err)
		}
	}

	return acc, nil
}

func multiplyByScalar(eval *bgv.Evaluator, ciphertext *rlwe.Ciphertext, scalar uint64) (*rlwe.Ciphertext, error) {
	if scalar == 0 {
		return nil, fmt.Errorf("scalar multiplication by zero is not supported")
	}
	if scalar == 1 {
		return ciphertext.CopyNew(), nil
	}

	result := ciphertext.CopyNew()
	if err := eval.Mul(result, scalar, result); err != nil {
		return nil, fmt.Errorf("multiply ciphertext by %d: %w", scalar, err)
	}
	return result, nil
}

func applyCirculantColumns(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	for row := 0; row < width; row++ {
		for col := 0; col < width; col++ {
			terms := make([]weightedCiphertext, width)
			for k := 0; k < width; k++ {
				terms[k] = weightedCiphertext{coeff: coeffs[k], ct: state[((row+k)%width)*width+col]}
			}

			combined, err := linearCombination(eval, terms)
			if err != nil {
				return nil, err
			}
			result[row*width+col] = combined
		}
	}
	return result, nil
}

func applyCirculantRows(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	for row := 0; row < width; row++ {
		for col := 0; col < width; col++ {
			terms := make([]weightedCiphertext, width)
			for k := 0; k < width; k++ {
				terms[k] = weightedCiphertext{coeff: coeffs[k], ct: state[row*width+((col+k)%width)]}
			}

			combined, err := linearCombination(eval, terms)
			if err != nil {
				return nil, err
			}
			result[row*width+col] = combined
		}
	}
	return result, nil
}

func applyCirculantLayer(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64) ([]*rlwe.Ciphertext, error) {
	columns, err := applyCirculantColumns(eval, state, width, coeffs)
	if err != nil {
		return nil, err
	}
	return applyCirculantRows(eval, columns, width, coeffs)
}

func cubeState(eval *bgv.Evaluator, state []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	for i, ciphertext := range state {
		square, err := eval.MulRelinNew(ciphertext, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("square state %d: %w", i, err)
		}

		cube, err := eval.MulRelinNew(square, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("cube state %d: %w", i, err)
		}

		result[i] = cube
	}
	return result, nil
}

func feistelState(eval *bgv.Evaluator, state []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	result := cloneCiphertexts(state)
	for i := 1; i < len(state); i++ {
		square, err := eval.MulRelinNew(state[i-1], state[i-1])
		if err != nil {
			return nil, fmt.Errorf("square feistel state %d: %w", i-1, err)
		}

		if err := eval.Add(result[i], square, result[i]); err != nil {
			return nil, fmt.Errorf("add feistel state %d: %w", i, err)
		}
	}

	return result, nil
}

func repeatUint(value uint64, slots int) []uint64 {
	values := make([]uint64, slots)
	for i := range values {
		values[i] = value
	}
	return values
}

func padUint(values []uint64, size int) []uint64 {
	if len(values) == size {
		copied := make([]uint64, size)
		copy(copied, values)
		return copied
	}

	padded := make([]uint64, size)
	copy(padded, values)
	return padded
}
