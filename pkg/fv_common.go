package pkg

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// baseCipher holds the shared BGV runtime and pre-allocated state template used by
// all FV cipher evaluators. cfg controls parallelism for all HE operations.
type baseCipher struct {
	runtime       *BGVRuntime
	blockSize     int
	outputSize    int
	stateTemplate []*rlwe.Ciphertext
	cfg           ParallelConfig
}

type weightedCiphertext struct {
	coeff uint64
	ct    *rlwe.Ciphertext
}

func newBaseCipher(runtime *BGVRuntime, blockSize, outputSize int, cfg ParallelConfig) (*baseCipher, error) {
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
		cfg:           cfg,
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

// addRoundKey adds round key i to state[i] for every i in [0, blockSize).
// The round constant is encoded as a plaintext, multiplied into a copy of
// encryptedKey[i], and added into state[i].
//
// Encoding is done serially (bgv.Encoder is not goroutine-safe); the resulting
// HE multiply+add is then parallelised using b.cfg.
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

	// Pre-encode all round-constant plaintexts serially (encoder is not goroutine-safe).
	plaintexts := make([]*rlwe.Plaintext, b.blockSize)
	for i := 0; i < b.blockSize; i++ {
		pt, err := b.runtime.encodeUint(padUint(roundConstants[i], b.runtime.Slots()))
		if err != nil {
			return err
		}
		plaintexts[i] = pt
	}

	// Parallelise the HE multiply + add per state element.
	// Each goroutine uses its own evaluator shallow-copy to avoid data races.
	return parallelDo(b.blockSize, b.cfg.MaxWorkers, b.cfg.Guard, func(i int) error {
		localEval := b.runtime.evaluator.ShallowCopy()
		roundKey := encryptedKey[i].CopyNew()
		if err := localEval.Mul(roundKey, plaintexts[i], roundKey); err != nil {
			return fmt.Errorf("multiply round key %d: %w", i, err)
		}
		if err := localEval.Add(state[i], roundKey, state[i]); err != nil {
			return fmt.Errorf("add round key %d: %w", i, err)
		}
		return nil
	})
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

// applyCirculantColumns applies the circulant column layer.
// Each output element result[row*width+col] is a linear combination of state elements
// in the same column — all reads are from the immutable state slice. Parallelised over
// rows using cfg; each row goroutine uses its own evaluator shallow-copy.
func applyCirculantColumns(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64, cfg ParallelConfig) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	err := parallelDo(width, cfg.MaxWorkers, cfg.Guard, func(row int) error {
		localEval := eval.ShallowCopy()
		for col := 0; col < width; col++ {
			terms := make([]weightedCiphertext, width)
			for k := 0; k < width; k++ {
				terms[k] = weightedCiphertext{coeff: coeffs[k], ct: state[((row+k)%width)*width+col]}
			}
			combined, err := linearCombination(localEval, terms)
			if err != nil {
				return err
			}
			result[row*width+col] = combined
		}
		return nil
	})
	return result, err
}

// applyCirculantRows applies the circulant row layer.
// Each output element result[row*width+col] is a linear combination of state elements
// in the same row — all reads are from the immutable state slice. Parallelised over
// rows using cfg; each row goroutine uses its own evaluator shallow-copy.
func applyCirculantRows(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64, cfg ParallelConfig) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	err := parallelDo(width, cfg.MaxWorkers, cfg.Guard, func(row int) error {
		localEval := eval.ShallowCopy()
		for col := 0; col < width; col++ {
			terms := make([]weightedCiphertext, width)
			for k := 0; k < width; k++ {
				terms[k] = weightedCiphertext{coeff: coeffs[k], ct: state[row*width+((col+k)%width)]}
			}
			combined, err := linearCombination(localEval, terms)
			if err != nil {
				return err
			}
			result[row*width+col] = combined
		}
		return nil
	})
	return result, err
}

// applyCirculantLayer applies columns then rows, both parallelised via cfg.
func applyCirculantLayer(eval *bgv.Evaluator, state []*rlwe.Ciphertext, width int, coeffs []uint64, cfg ParallelConfig) ([]*rlwe.Ciphertext, error) {
	columns, err := applyCirculantColumns(eval, state, width, coeffs, cfg)
	if err != nil {
		return nil, err
	}
	return applyCirculantRows(eval, columns, width, coeffs, cfg)
}

// cubeState squares then cubes each ciphertext element independently.
// Reads from the immutable state slice; writes to disjoint result slots.
// Parallelised over state elements using cfg; each goroutine uses its own evaluator copy.
func cubeState(eval *bgv.Evaluator, state []*rlwe.Ciphertext, cfg ParallelConfig) ([]*rlwe.Ciphertext, error) {
	result := make([]*rlwe.Ciphertext, len(state))
	err := parallelDo(len(state), cfg.MaxWorkers, cfg.Guard, func(i int) error {
		localEval := eval.ShallowCopy()
		square, err := localEval.MulRelinNew(state[i], state[i])
		if err != nil {
			return fmt.Errorf("square state %d: %w", i, err)
		}
		cube, err := localEval.MulRelinNew(square, state[i])
		if err != nil {
			return fmt.Errorf("cube state %d: %w", i, err)
		}
		result[i] = cube
		return nil
	})
	return result, err
}

// feistelState applies the Feistel S-box: result[i] += state[i-1]^2 for i >= 1.
// result[0] is an unchanged copy of state[0]. The source slice (state) is never
// modified, so all indices i >= 1 are independent and parallelised via cfg.
func feistelState(eval *bgv.Evaluator, state []*rlwe.Ciphertext, cfg ParallelConfig) ([]*rlwe.Ciphertext, error) {
	result := cloneCiphertexts(state)
	if len(state) <= 1 {
		return result, nil
	}
	// Parallelise i = 1..len(state)-1.  j is 0-based to fit parallelDo's signature.
	err := parallelDo(len(state)-1, cfg.MaxWorkers, cfg.Guard, func(j int) error {
		i := j + 1 // actual state index
		localEval := eval.ShallowCopy()
		square, err := localEval.MulRelinNew(state[i-1], state[i-1])
		if err != nil {
			return fmt.Errorf("square feistel state %d: %w", i-1, err)
		}
		if err := localEval.Add(result[i], square, result[i]); err != nil {
			return fmt.Errorf("add feistel state %d: %w", i, err)
		}
		return nil
	})
	return result, err
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
