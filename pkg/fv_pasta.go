package pkg

import (
	"fmt"
	"math/bits"

	sympasta "github.com/hosseinabdinf/sherdal/ske/pasta"

	"github.com/hosseinabdinf/sherdal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/crypto/sha3"
)

// FVPastaEvaluator evaluates the modular PASTA keystream homomorphically over BGV.
//
// PASTA state layout:
//   - Full state size = KeySize (e.g. 64) = state1 (BlockSize=32) + state2 (BlockSize=32)
//   - Initial state  = the encrypted symmetric key (state IS the key)
//   - Output         = first BlockSize ciphertexts (state1) after all rounds
//
// Round structure (Rounds=4 example):
//
//	linLayer → feistel → linLayer → feistel → linLayer → feistel → linLayer → cube → linLayer
type FVPastaEvaluator struct {
	base   *baseCipher
	params sympasta.Parameter
	cfg    ParallelConfig
}

// NewFVPastaEvaluator creates and initialises a new FVPastaEvaluator with serial execution.
// In ske/pasta Parameter:
//
//	KeySize  = full cipher state (state1 + state2), e.g. 64
//	BlockSize = one half-state = output keystream size, e.g. 32
//
// KeySize must equal 2 * BlockSize.
func NewFVPastaEvaluator(runtime *BGVRuntime, params sympasta.Parameter) (*FVPastaEvaluator, error) {
	return NewFVPastaEvaluatorWithConfig(runtime, params, SerialConfig())
}

// NewFVPastaEvaluatorWithConfig creates a new FVPastaEvaluator with the given parallel config.
// See NewFVPastaEvaluator for parameter constraints.
func NewFVPastaEvaluatorWithConfig(runtime *BGVRuntime, params sympasta.Parameter, cfg ParallelConfig) (*FVPastaEvaluator, error) {
	if params.BlockSize <= 0 || params.KeySize != 2*params.BlockSize {
		return nil, fmt.Errorf("PASTA KeySize must equal 2*BlockSize, got KeySize=%d BlockSize=%d",
			params.KeySize, params.BlockSize)
	}

	// baseCipher blockSize  = full state (KeySize elements)
	// baseCipher outputSize = half-state returned as keystream (BlockSize elements)
	base, err := newBaseCipher(runtime, params.KeySize, params.BlockSize, cfg)
	if err != nil {
		return nil, err
	}

	return &FVPastaEvaluator{base: base, params: params, cfg: cfg}, nil
}

// EncryptKey encrypts each element of the symmetric key using the BGV runtime.
// The key slice must have exactly params.KeySize elements (the full key = state1 + state2).
// Returns a slice of KeySize ciphertexts, or an error if encryption fails.
func (p *FVPastaEvaluator) EncryptKey(key []uint64) ([]*rlwe.Ciphertext, error) {
	return p.base.EncryptKey(key)
}

// Crypt evaluates the PASTA keystream for the given nonces and counter.
// Each nonce drives one slot lane; the same counter is broadcast to all lanes.
// encryptedKey must be the output of EncryptKey (KeySize ciphertexts).
// Returns BlockSize keystream ciphertexts (state1 half only).
func (p *FVPastaEvaluator) Crypt(nonces [][]byte, counter []byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	counters := make([][]byte, len(nonces))
	for i := range counters {
		counters[i] = counter
	}
	return p.CryptWithCounters(nonces, counters, encryptedKey)
}

// CryptWithCounters is the per-lane counter variant of Crypt.
// nonces[i] and counters[i] together seed the SHAKE128 stream for slot lane i.
// encryptedKey must be the output of EncryptKey (KeySize ciphertexts).
// Returns BlockSize keystream ciphertexts (state1 half only).
func (p *FVPastaEvaluator) CryptWithCounters(nonces [][]byte, counters [][]byte, encryptedKey []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	rc, mat1, mat2 := p.roundData(nonces, counters)

	// PASTA initial state IS the encrypted key — do NOT use baseCipher.initialState().
	// state[0..T-1] = state1 (first half of key), state[T..2T-1] = state2 (second half).
	state := cloneCiphertexts(encryptedKey)
	eval := p.base.runtime.evaluator

	var err error

	// Round 0: initial linear layer (no S-box precedes it).
	state, err = p.pastaLinLayer(eval, state, rc[0], mat1[0], mat2[0])
	if err != nil {
		return nil, fmt.Errorf("PASTA linear layer round 0: %w", err)
	}

	// Rounds 1 .. Rounds-1: Feistel S-box then linear layer.
	for round := 1; round < p.params.Rounds; round++ {
		state, err = feistelState(eval, state, p.cfg)
		if err != nil {
			return nil, fmt.Errorf("PASTA Feistel S-box round %d: %w", round, err)
		}

		state, err = p.pastaLinLayer(eval, state, rc[round], mat1[round], mat2[round])
		if err != nil {
			return nil, fmt.Errorf("PASTA linear layer round %d: %w", round, err)
		}
	}

	// Final S-box: cube (applied to whole state), then one last linear layer.
	state, err = cubeState(eval, state, p.cfg)
	if err != nil {
		return nil, fmt.Errorf("PASTA cube S-box: %w", err)
	}

	state, err = p.pastaLinLayer(eval, state, rc[p.params.Rounds], mat1[p.params.Rounds], mat2[p.params.Rounds])
	if err != nil {
		return nil, fmt.Errorf("PASTA linear layer final: %w", err)
	}

	// Output is the first T = BlockSize ciphertexts (state1 half).
	return append([]*rlwe.Ciphertext(nil), state[:p.base.outputSize]...), nil
}

// pastaLinLayer applies one PASTA linear layer over BGV ciphertexts.
//
// PASTA's linear layer is applied independently to each half-state:
//  1. Multiply each half by its per-round random companion matrix (mat1 for state1, mat2 for state2).
//     Matrix coefficients are PUBLIC — encoded as BGV plaintexts (not ciphertexts).
//  2. Add the additive round constants (also public plaintexts) to each element.
//  3. Mix: sum[i] = s1[i]+s2[i]; s1[i] += sum[i]; s2[i] += sum[i].
//
// Parameters rc, mat1, mat2 are indexed as [stateElement][lane] and [row][col][lane].
//
// Parallelisation strategy:
//   - All matrix plaintext encodings are performed serially (bgv.Encoder is not goroutine-safe).
//   - Row accumulations for state1 and state2 are then parallelised over (half, row) pairs.
//   - The final mix step is parallelised over element index i.
//   - Each goroutine uses its own evaluator shallow-copy.
func (p *FVPastaEvaluator) pastaLinLayer(
	eval *bgv.Evaluator,
	state []*rlwe.Ciphertext,
	rc [][]uint64,
	mat1 [][][]uint64,
	mat2 [][][]uint64,
) ([]*rlwe.Ciphertext, error) {
	T := p.base.outputSize // BlockSize (one half-state)
	slots := p.base.runtime.Slots()
	cfg := p.cfg

	encode := func(v []uint64) (*rlwe.Plaintext, error) {
		return p.base.runtime.encodeUint(padUint(v, slots))
	}

	// ── Pre-encode all plaintexts serially (encoder is not goroutine-safe) ──────
	mat1PT := make([][]*rlwe.Plaintext, T)
	mat2PT := make([][]*rlwe.Plaintext, T)
	for row := 0; row < T; row++ {
		mat1PT[row] = make([]*rlwe.Plaintext, T)
		mat2PT[row] = make([]*rlwe.Plaintext, T)
		for col := 0; col < T; col++ {
			pt, err := encode(mat1[row][col])
			if err != nil {
				return nil, fmt.Errorf("encode mat1 row=%d col=%d: %w", row, col, err)
			}
			mat1PT[row][col] = pt

			pt, err = encode(mat2[row][col])
			if err != nil {
				return nil, fmt.Errorf("encode mat2 row=%d col=%d: %w", row, col, err)
			}
			mat2PT[row][col] = pt
		}
	}

	rcPT := make([]*rlwe.Plaintext, 2*T)
	for i := 0; i < 2*T; i++ {
		pt, err := encode(rc[i])
		if err != nil {
			return nil, fmt.Errorf("encode rc[%d]: %w", i, err)
		}
		rcPT[i] = pt
	}

	// ── Parallel row accumulation: 2*T independent (half, row) tasks ────────────
	// newState[half*T+row] is written by exactly one goroutine.
	newState := make([]*rlwe.Ciphertext, p.base.blockSize)
	if err := parallelDo(2*T, cfg.MaxWorkers, cfg.Guard, func(idx int) error {
		half := idx / T
		row := idx % T

		var matPT [][]*rlwe.Plaintext
		if half == 0 {
			matPT = mat1PT
		} else {
			matPT = mat2PT
		}

		localEval := eval.ShallowCopy()
		var rowAcc *rlwe.Ciphertext

		for col := 0; col < T; col++ {
			stateIdx := half*T + col
			prod := state[stateIdx].CopyNew()
			if err := localEval.Mul(prod, matPT[row][col], prod); err != nil {
				return fmt.Errorf("mul mat half=%d row=%d col=%d: %w", half, row, col, err)
			}
			if rowAcc == nil {
				rowAcc = prod
			} else {
				if err := localEval.Add(rowAcc, prod, rowAcc); err != nil {
					return fmt.Errorf("add mat term half=%d row=%d col=%d: %w", half, row, col, err)
				}
			}
		}

		if err := localEval.Add(rowAcc, rcPT[half*T+row], rowAcc); err != nil {
			return fmt.Errorf("add rc half=%d row=%d: %w", half, row, err)
		}

		newState[half*T+row] = rowAcc
		return nil
	}); err != nil {
		return nil, err
	}

	// ── Parallel mix: sum[i] = s1[i]+s2[i]; s1[i] += sum; s2[i] += sum ─────────
	// Index i accesses only newState[i] and newState[T+i], which are disjoint.
	if err := parallelDo(T, cfg.MaxWorkers, cfg.Guard, func(i int) error {
		localEval := eval.ShallowCopy()
		sum, err := localEval.AddNew(newState[i], newState[T+i])
		if err != nil {
			return fmt.Errorf("mix sum[%d]: %w", i, err)
		}
		if err := localEval.Add(newState[i], sum, newState[i]); err != nil {
			return fmt.Errorf("mix update state1[%d]: %w", i, err)
		}
		if err := localEval.Add(newState[T+i], sum, newState[T+i]); err != nil {
			return fmt.Errorf("mix update state2[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return newState, nil
}

// roundData pre-samples all pseudorandom material needed for every PASTA round.
//
// Sampling order matches the original FV PASTA (_old_fv_org/fv_pasta.go):
//  1. ALL round constants first — for rounds 0..Rounds, for all bs state elements.
//  2. ALL matrices next   — for rounds 0..Rounds, companion matrix for state1 then state2.
//
// Companion matrix structure (same as GetRandomMatrixPasta in _old_fv_org/utils.go):
//   - Row 0: T uniformly random field elements.
//   - Rows 1..T-1: derived from the previous row and row 0 via pastaCalculateRow.
//
// Result shapes:
//
//	rc   [round][stateElement][lane]
//	mat1 [round][row][col][lane]  (state1 matrix)
//	mat2 [round][row][col][lane]  (state2 matrix)
//
// Each lane owns an independent SHAKE128 stream and writes to disjoint tensor positions,
// so all lanes are processed in parallel using p.cfg.
func (p *FVPastaEvaluator) roundData(nonces [][]byte, counters [][]byte) (
	rc [][][]uint64,
	mat1 [][][][]uint64,
	mat2 [][][][]uint64,
) {
	T := p.base.outputSize // BlockSize (half-state)
	bs := p.base.blockSize // KeySize  (full state = 2*T)
	rounds := p.params.Rounds
	lanes := len(nonces)
	modulus := p.params.Modulus

	// Allocate output slices.
	rc = make([][][]uint64, rounds+1)
	mat1 = make([][][][]uint64, rounds+1)
	mat2 = make([][][][]uint64, rounds+1)
	for r := 0; r <= rounds; r++ {
		rc[r] = make([][]uint64, bs)
		for s := 0; s < bs; s++ {
			rc[r][s] = make([]uint64, lanes)
		}
		mat1[r] = make([][][]uint64, T)
		mat2[r] = make([][][]uint64, T)
		for row := 0; row < T; row++ {
			mat1[r][row] = make([][]uint64, T)
			mat2[r][row] = make([][]uint64, T)
			for col := 0; col < T; col++ {
				mat1[r][row][col] = make([]uint64, lanes)
				mat2[r][row][col] = make([]uint64, lanes)
			}
		}
	}

	// Parallelise over lanes: each goroutine writes only to [*][*][lane].
	_ = parallelDo(lanes, p.cfg.MaxWorkers, p.cfg.Guard, func(lane int) error {
		shake := sha3.NewShake128()
		_, _ = shake.Write(nonces[lane])
		if lane < len(counters) && counters[lane] != nil {
			_, _ = shake.Write(counters[lane])
		}

		// ── Phase 1: sample ALL round constants first ──────────────────────────
		// Matches old FV: rc[r][st][slot] for all r then all st then all slots.
		for r := 0; r <= rounds; r++ {
			for s := 0; s < bs; s++ {
				rc[r][s][lane] = utils.SampleZqx(shake, modulus)
			}
		}

		// ── Phase 2: sample companion matrices for all rounds ──────────────────
		// Matches old FV: for each round, GetRandomMatrixPasta(T) for mat1 then mat2.
		for r := 0; r <= rounds; r++ {
			// mat1: sample first row, derive rows 1..T-1.
			firstRow := make([]uint64, T)
			for col := 0; col < T; col++ {
				firstRow[col] = utils.SampleZqx(shake, modulus)
				mat1[r][0][col][lane] = firstRow[col]
			}
			for row := 1; row < T; row++ {
				prev := make([]uint64, T)
				for col := 0; col < T; col++ {
					prev[col] = mat1[r][row-1][col][lane]
				}
				derived := pastaCalculateRow(prev, firstRow, modulus)
				for col := 0; col < T; col++ {
					mat1[r][row][col][lane] = derived[col]
				}
			}

			// mat2: same companion-matrix structure.
			firstRow2 := make([]uint64, T)
			for col := 0; col < T; col++ {
				firstRow2[col] = utils.SampleZqx(shake, modulus)
				mat2[r][0][col][lane] = firstRow2[col]
			}
			for row := 1; row < T; row++ {
				prev := make([]uint64, T)
				for col := 0; col < T; col++ {
					prev[col] = mat2[r][row-1][col][lane]
				}
				derived := pastaCalculateRow(prev, firstRow2, modulus)
				for col := 0; col < T; col++ {
					mat2[r][row][col][lane] = derived[col]
				}
			}
		}
		return nil
	})

	return rc, mat1, mat2
}

func mulMod(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, m)
	return rem
}

func addMod(a, b, m uint64) uint64 {
	res := a + b
	if res >= m {
		res -= m
	}
	return res
}

// pastaCalculateRow derives the next companion-matrix row from the previous row and
// the first row, matching _old_fv_org.calculateRow exactly:
//
//	out[i] = firstRow[i] * prevRow[T-1] + (i > 0 ? prevRow[i-1] : 0)   (mod modulus)
func pastaCalculateRow(prevRow, firstRow []uint64, modulus uint64) []uint64 {
	T := len(prevRow)
	out := make([]uint64, T)
	last := prevRow[T-1]

	for i := 0; i < T; i++ {
		tmp := mulMod(firstRow[i], last, modulus)
		if i > 0 {
			tmp = addMod(tmp, prevRow[i-1], modulus)
		}
		out[i] = tmp
	}
	return out
}
