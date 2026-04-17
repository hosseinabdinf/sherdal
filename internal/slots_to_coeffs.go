package internal

import (
	"fmt"
	"sort"

	bgvlin "github.com/tuneinsight/lattigo/v6/circuits/bgv/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	tring "github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type SlotToCoeffTransformer struct {
	runtime    *BGVRuntime
	logFVSlots int
	modDown    []int
	evaluator  *bgv.Evaluator
	ltEval     *bgvlin.Evaluator
	matrices   map[int][]bgvlin.LinearTransformation
}

func NewSlotToCoeffTransformer(runtime *BGVRuntime, logFVSlots int, modDown []int) (*SlotToCoeffTransformer, error) {
	if logFVSlots != runtime.params.LogMaxSlots() {
		return nil, fmt.Errorf("logFVSlots=%d not supported yet, expected full-coefficient mode %d", logFVSlots, runtime.params.LogMaxSlots())
	}

	baseDiagonals := genDcdMatsRad2(logFVSlots, runtime.params.PlaintextModulus())
	if len(baseDiagonals) < 2 {
		return nil, fmt.Errorf("invalid slot-to-coeff diagonal depth %d", len(baseDiagonals))
	}

	matrices := make(map[int][]bgvlin.LinearTransformation, runtime.params.MaxLevel()+1)
	galElSet := map[uint64]struct{}{}

	for level := 0; level <= runtime.params.MaxLevel(); level++ {
		transforms := make([]bgvlin.LinearTransformation, len(baseDiagonals))
		for i, diagonals := range baseDiagonals {
			ltParams := bgvlin.Parameters{
				DiagonalsIndexList:        bgvlin.Diagonals[uint64](diagonals).DiagonalsIndexList(),
				LevelQ:                    level,
				LevelP:                    runtime.params.MaxLevelP(),
				Scale:                     runtime.params.DefaultScale(),
				LogDimensions:             runtime.params.LogMaxDimensions(),
				LogBabyStepGiantStepRatio: 1,
			}

			transform := bgvlin.NewLinearTransformation(runtime.params, ltParams)
			if err := bgvlin.Encode(runtime.encoder, bgvlin.Diagonals[uint64](diagonals), transform); err != nil {
				return nil, fmt.Errorf("encode slot-to-coeff matrix at level %d depth %d: %w", level, i, err)
			}

			for _, galEl := range transform.GaloisElements(runtime.params) {
				galElSet[galEl] = struct{}{}
			}
			transforms[i] = transform
		}
		matrices[level] = transforms
	}

	galElSet[runtime.params.GaloisElementForRowRotation()] = struct{}{}
	galEls := make([]uint64, 0, len(galElSet))
	for galEl := range galElSet {
		galEls = append(galEls, galEl)
	}
	sort.Slice(galEls, func(i, j int) bool { return galEls[i] < galEls[j] })

	kgen := rlwe.NewKeyGenerator(runtime.params)
	gks := kgen.GenGaloisKeysNew(galEls, runtime.sk)
	evk := rlwe.NewMemEvaluationKeySet(runtime.rlk, gks...)
	evaluator := runtime.evaluator.WithKey(evk)

	return &SlotToCoeffTransformer{
		runtime:    runtime,
		logFVSlots: logFVSlots,
		modDown:    append([]int(nil), modDown...),
		evaluator:  evaluator,
		ltEval:     bgvlin.NewEvaluator(evaluator),
		matrices:   matrices,
	}, nil
}

func (t *SlotToCoeffTransformer) Transform(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if ct == nil {
		return nil, fmt.Errorf("ciphertext is nil")
	}

	ctOut := ct.CopyNew()
	level := ctOut.Level()
	transforms := t.matrices[level]
	depth := len(transforms) - 1
	if depth < 1 {
		return nil, fmt.Errorf("invalid transform depth %d", depth)
	}

	for i := 0; i < depth-1; i++ {
		if i < len(t.modDown) && t.modDown[i] > 0 {
			t.evaluator.DropLevel(ctOut, t.modDown[i])
		}
		level = ctOut.Level()
		var err error
		ctOut, err = t.ltEval.EvaluateNew(ctOut, t.matrices[level][i])
		if err != nil {
			return nil, fmt.Errorf("slots-to-coeff transform depth %d: %w", i, err)
		}
	}

	if depth-1 < len(t.modDown) && t.modDown[depth-1] > 0 {
		t.evaluator.DropLevel(ctOut, t.modDown[depth-1])
	}
	level = ctOut.Level()
	tmp, err := t.evaluator.RotateRowsNew(ctOut)
	if err != nil {
		return nil, fmt.Errorf("rotate rows: %w", err)
	}

	ctOut, err = t.ltEval.EvaluateNew(ctOut, t.matrices[level][depth-1])
	if err != nil {
		return nil, fmt.Errorf("slots-to-coeff final transform: %w", err)
	}
	tmp, err = t.ltEval.EvaluateNew(tmp, t.matrices[level][depth])
	if err != nil {
		return nil, fmt.Errorf("slots-to-coeff rotated final transform: %w", err)
	}

	if err := t.evaluator.Add(ctOut, tmp, ctOut); err != nil {
		return nil, fmt.Errorf("combine slots-to-coeff outputs: %w", err)
	}

	return ctOut, nil
}

func (t *SlotToCoeffTransformer) TransformAll(ciphertexts []*rlwe.Ciphertext) ([]*rlwe.Ciphertext, error) {
	out := make([]*rlwe.Ciphertext, len(ciphertexts))
	for i, ct := range ciphertexts {
		transformed, err := t.Transform(ct)
		if err != nil {
			return nil, fmt.Errorf("transform ciphertext %d: %w", i, err)
		}
		out[i] = transformed
	}
	return out, nil
}

func genDcdMatsRad2(logSlots int, plainModulus uint64) []map[int][]uint64 {
	roots := computePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := genDcdDiabDecomp(logSlots, roots)
	depth := len(diabMats) - 1

	plainVector := make([]map[int][]uint64, (depth+1)/2+1)
	if depth%2 == 0 {
		for i := 0; i < depth-2; i += 2 {
			plainVector[i/2] = multDiabMats(diabMats[i+1], diabMats[i], plainModulus)
		}
	} else {
		plainVector[0] = diabMats[0]
		for i := 1; i < depth-2; i += 2 {
			plainVector[(i+1)/2] = multDiabMats(diabMats[i+1], diabMats[i], plainModulus)
		}
	}
	plainVector[(depth-1)/2] = multDiabMats(diabMats[depth-1], diabMats[depth-2], plainModulus)
	plainVector[(depth+1)/2] = multDiabMats(diabMats[depth], diabMats[depth-2], plainModulus)
	return plainVector
}

func multDiabMats(a, b map[int][]uint64, plainModulus uint64) map[int][]uint64 {
	res := make(map[int][]uint64)
	for rotA := range a {
		for rotB := range b {
			n := len(a[rotA])
			rot := (rotA + rotB) % (n / 2)
			if res[rot] == nil {
				res[rot] = make([]uint64, n)
			}
			for i := 0; i < n/2; i++ {
				res[rot][i] += a[rotA][i] * b[rotB][(rotA+i)%(n/2)]
				res[rot][i] %= plainModulus
			}
			for i := n / 2; i < n; i++ {
				res[rot][i] += a[rotA][i] * b[rotB][n/2+(rotA+i)%(n/2)]
				res[rot][i] %= plainModulus
			}
		}
	}
	return res
}

func genDcdDiabDecomp(logN int, roots []uint64) []map[int][]uint64 {
	n := 1 << logN
	m := 2 * n
	pow5 := make([]int, m)
	res := make([]map[int][]uint64, logN)

	for i, exp5 := 0, 1; i < n; i, exp5 = i+1, exp5*5%m {
		pow5[i] = exp5
	}

	res[0] = make(map[int][]uint64)
	for _, rot := range []int{0, 1, 2, 3, n/2 - 1, n/2 - 2, n/2 - 3} {
		res[0][rot] = make([]uint64, n)
	}

	for i := 0; i < n; i += 4 {
		res[0][0][i] = 1
		res[0][0][i+1] = roots[2*n/4]
		res[0][0][i+2] = roots[7*n/4]
		res[0][0][i+3] = roots[n/4]

		res[0][1][i] = roots[2*n/4]
		res[0][1][i+1] = roots[5*n/4]
		res[0][1][i+2] = roots[5*n/4]

		res[0][2][i] = roots[n/4]
		res[0][2][i+1] = roots[7*n/4]

		res[0][3][i] = roots[3*n/4]

		res[0][n/2-1][i+1] = 1
		res[0][n/2-1][i+2] = roots[6*n/4]
		res[0][n/2-1][i+3] = roots[3*n/4]

		res[0][n/2-2][i+2] = 1
		res[0][n/2-2][i+3] = roots[6*n/4]

		res[0][n/2-3][i+3] = 1
	}

	for ind := 1; ind < logN-2; ind++ {
		s := 1 << ind
		gap := n / s / 4
		res[ind] = make(map[int][]uint64)
		for _, rot := range []int{0, s, 2 * s, n/2 - s, n/2 - 2*s} {
			res[ind][rot] = make([]uint64, n)
		}

		for i := 0; i < n; i += 4 * s {
			for j := 0; j < s; j++ {
				res[ind][2*s][i+j] = roots[pow5[j]*gap%m]
				res[ind][s][i+s+j] = roots[pow5[s+j]*gap%m]
				res[ind][s][i+2*s+j] = roots[m-pow5[j]*gap%m]
				res[ind][0][i+j] = 1
				res[ind][0][i+3*s+j] = roots[m-pow5[s+j]*gap%m]
				res[ind][n/2-s][i+s+j] = 1
				res[ind][n/2-s][i+2*s+j] = 1
				res[ind][n/2-2*s][i+3*s+j] = 1
			}
		}
	}

	s := n / 4
	res[logN-2] = map[int][]uint64{0: make([]uint64, n), s: make([]uint64, n)}
	res[logN-1] = map[int][]uint64{0: make([]uint64, n), s: make([]uint64, n)}
	for i := 0; i < s; i++ {
		res[logN-2][0][i] = 1
		res[logN-2][0][i+3*s] = roots[m-pow5[s+i]%m]
		res[logN-2][s][i+s] = 1
		res[logN-2][s][i+2*s] = roots[m-pow5[i]%m]

		res[logN-1][0][i] = roots[pow5[i]%m]
		res[logN-1][0][i+3*s] = 1
		res[logN-1][s][i+s] = roots[pow5[s+i]%m]
		res[logN-1][s][i+2*s] = 1
	}

	return res
}

func computePrimitiveRoots(m int, plainModulus uint64) []uint64 {
	g, _, err := tring.PrimitiveRoot(plainModulus, nil)
	if err != nil {
		panic(err)
	}
	w := tring.ModExp(g, uint64((int(plainModulus)-1)/m), plainModulus)
	roots := make([]uint64, m)
	roots[0] = 1
	for i := 1; i < m; i++ {
		roots[i] = (roots[i-1] * w) % plainModulus
	}
	return roots
}
