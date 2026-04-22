package hera

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/internal"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"

	"github.com/stretchr/testify/require"
)

func TestHeraEvalKeystreamSmoke(t *testing.T) {
	heHera, err := NewHera(Config{Preset: Hera128AF, BGVLogN: 14, SymmetricParams: symhera.Hera4Params2516})
	require.NoError(t, err)

	key := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	require.NoError(t, heHera.EncryptSymmetricKey(key))

	nonces := internal.DeterministicNonces(1, 64)
	ciphertexts, err := heHera.EvalKeystream(nonces)
	require.NoError(t, err)

	got, err := heHera.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)
	require.Len(t, ciphertexts, symhera.Hera4Params2516.BlockSize)
	require.Len(t, got, len(nonces))
	require.Len(t, got[0], symhera.Hera4Params2516.BlockSize)
}

func TestHeraHalfBootSpecBuildsParameters(t *testing.T) {
	spec := DefaultHeraConfig(Hera128AF, symhera.Hera4Params2516).HalfBootSpec()
	_, err := spec.ResidualParameters()
	require.NoError(t, err)
	require.Equal(t, spec.LogSlots, *spec.BootstrappingLiteral().LogSlots)
}
