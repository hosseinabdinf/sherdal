package pasta

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/pkg"

	"github.com/hosseinabdinf/sherdal/ske/pasta"

	"github.com/stretchr/testify/require"
)

func TestPastaEvalKeystreamSmoke(t *testing.T) {
	hePasta, err := NewPasta(Config{Preset: Pasta4_1614, BGVLogN: 14, SymmetricParams: pasta.Pasta4Param1614})
	require.NoError(t, err)

	key := make([]uint64, pasta.Pasta4Param1614.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	require.NoError(t, hePasta.EncryptSymmetricKey(key))

	nonces := pkg.DeterministicNonces(1, 8)
	counter := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	ciphertexts, err := hePasta.EvalKeystream(nonces, counter)
	require.NoError(t, err)

	got, err := hePasta.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)
	require.Len(t, ciphertexts, pasta.Pasta4Param1614.BlockSize)
	require.Len(t, got, len(nonces))
	require.Len(t, got[0], pasta.Pasta4Param1614.BlockSize)
}

func TestPastaEvalKeystreamParallelSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parallel pasta smoke test in short mode")
	}
	hePasta, err := NewPastaWithConfig(
		Config{Preset: Pasta4_1614, BGVLogN: 14, SymmetricParams: pasta.Pasta4Param1614},
		pkg.ParallelConfig{MaxWorkers: 4},
	)
	require.NoError(t, err)

	key := make([]uint64, pasta.Pasta4Param1614.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	require.NoError(t, hePasta.EncryptSymmetricKey(key))

	nonces := pkg.DeterministicNonces(1, 8)
	counter := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	ciphertexts, err := hePasta.EvalKeystream(nonces, counter)
	require.NoError(t, err)

	got, err := hePasta.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)
	require.Len(t, ciphertexts, pasta.Pasta4Param1614.BlockSize)
	require.Len(t, got, len(nonces))
	require.Len(t, got[0], pasta.Pasta4Param1614.BlockSize)
}

func TestPastaHalfBootSpecBuildsParameters(t *testing.T) {
	spec := DefaultPastaConfig(Pasta4_1614, pasta.Pasta4Param1614).halfBootSpec()
	_, err := spec.ResidualParameters()
	require.NoError(t, err)
	require.Equal(t, spec.LogSlots, *spec.BootstrappingLiteral().LogSlots)
}
