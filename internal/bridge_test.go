package internal

import (
	"sherdal/hhe/hera"
	"sherdal/hhe/rubato"
	symhera "sherdal/ske/hera"
	symrubato "sherdal/ske/rubato"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBridgeRequiresAlignedRuntime(t *testing.T) {
	heHera, err := hera.NewHera(hera.Config{Preset: hera.Hera128AF, BGVLogN: 14, SymmetricParams: symhera.Hera4Params2516})
	require.NoError(t, err)

	_, err = heHera.NewBridge()
	require.Error(t, err)
}

func TestBridgeBuildsHalfBootInput(t *testing.T) {
	heHera, err := hera.NewHera(hera.Config{Preset: hera.Hera128AF, UseResidualBGV: true, SymmetricParams: symhera.Hera4Params2516})
	require.NoError(t, err)

	bridge, err := heHera.NewBridge()
	require.NoError(t, err)

	coeffCipher, err := bridge.EncryptCoefficientCiphertext(make([]uint64, bridge.residual.N()))
	require.NoError(t, err)

	values := PackCoefficientsBitReversed([]float64{0.25, -0.5, 0.75, 0.0}, 2)
	ct, err := bridge.BuildHalfBootInput(values, coeffCipher)
	require.NoError(t, err)
	require.Equal(t, 0, ct.Level())
	require.True(t, ct.IsNTT)
	require.Equal(t, bridge.InputScale(), ct.Scale.Float64())
	_, err = heHera.NewHalfBootstrapper()
	require.NoError(t, err)
}

func TestRubatoEvalKeystreamCoeffsSmoke(t *testing.T) {
	heRubato, err := rubato.NewRubato(rubato.Config{Preset: rubato.Rubato128S, UseResidualBGV: true, SymmetricParams: symrubato.Parameter{LogN: 16, BlockSize: 16, Modulus: symrubato.Rubato5Param2616.Modulus, Rounds: 2, Sigma: 0}})
	require.NoError(t, err)

	key := []uint64{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16}
	require.NoError(t, heRubato.EncryptSymmetricKey(key))

	cts, err := heRubato.EvalKeystreamCoeffs(DeterministicNonces(1, 8), []byte{0, 1, 2, 3, 4, 5, 6, 7})
	require.NoError(t, err)
	require.Len(t, cts, 12)
	for _, ct := range cts {
		require.NotNil(t, ct)
	}
}
