package rubato

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/internal"

	"github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/stretchr/testify/require"
)

func TestRubatoMatchesPlaintext(t *testing.T) {
	heRubato, err := NewRubato(Config{Preset: Rubato80S, BGVLogN: 14, SymmetricParams: rubato.Parameter{LogN: 14, BlockSize: 16, Modulus: rubato.Rubato5Param2616.Modulus, Rounds: 2, Sigma: 0}})
	require.NoError(t, err)

	key := []uint64{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16}
	require.NoError(t, heRubato.EncryptSymmetricKey(key))

	nonces := internal.DeterministicNonces(6, 8)
	counter := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	ciphertexts, err := heRubato.EvalKeystream(nonces, counter)
	require.NoError(t, err)

	got, err := heRubato.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)

	plain := rubato.NewRubato(key, rubato.Parameter{LogN: 14, BlockSize: 16, Modulus: rubato.Rubato5Param2616.Modulus, Rounds: 2, Sigma: 0})
	for lane, nonce := range nonces {
		require.Equal(t, []uint64(plain.KeyStream(nonce, counter)), got[lane])
	}
}

func TestRubatoHalfBootSpecBuildsParameters(t *testing.T) {
	spec := DefaultRubatoConfig(Rubato128S, rubato.Rubato5Param2616).halfBootSpec()
	_, err := spec.ResidualParameters()
	require.NoError(t, err)
	require.Equal(t, spec.LogSlots, *spec.BootstrappingLiteral().LogSlots)
}
