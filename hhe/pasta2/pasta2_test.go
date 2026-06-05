package pasta2

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/pkg"

	sympasta2 "github.com/hosseinabdinf/sherdal/ske/pasta2"

	"github.com/stretchr/testify/require"
)

func TestPasta2EvalKeystreamSmoke(t *testing.T) {
	hePasta, err := NewPasta2(Config{Preset: Pasta2_4_1614, BGVLogN: 14, SymmetricParams: sympasta2.Pasta4Param1614})
	require.NoError(t, err)

	key := make([]uint64, sympasta2.Pasta4Param1614.KeySize)
	for i := range key {
		key[i] = uint64((i*17 + 3) % int(sympasta2.Pasta4Param1614.Modulus))
	}
	require.NoError(t, hePasta.EncryptSymmetricKey(key))

	// In Pasta2, the nonce input to EvalKeystream has length 2*ske.NonceSize = 16 bytes.
	nonces := [][]byte{
		sympasta2.NonceCounterSeed([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0),
	}
	ciphertexts, err := hePasta.EvalKeystream(nonces)
	require.NoError(t, err)

	got, err := hePasta.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)
	require.Len(t, ciphertexts, sympasta2.Pasta4Param1614.BlockSize)
	require.Len(t, got, len(nonces))
	require.Len(t, got[0], sympasta2.Pasta4Param1614.BlockSize)
}

func TestPasta2EvalKeystreamParallelSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parallel pasta2 smoke test in short mode")
	}
	hePasta, err := NewPasta2WithConfig(
		Config{Preset: Pasta2_4_1614, BGVLogN: 14, SymmetricParams: sympasta2.Pasta4Param1614},
		pkg.ParallelConfig{MaxWorkers: 4},
	)
	require.NoError(t, err)

	key := make([]uint64, sympasta2.Pasta4Param1614.KeySize)
	for i := range key {
		key[i] = uint64((i*17 + 3) % int(sympasta2.Pasta4Param1614.Modulus))
	}
	require.NoError(t, hePasta.EncryptSymmetricKey(key))

	nonces := [][]byte{
		sympasta2.NonceCounterSeed([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0),
	}
	ciphertexts, err := hePasta.EvalKeystream(nonces)
	require.NoError(t, err)

	got, err := hePasta.DecryptKeystream(ciphertexts, len(nonces))
	require.NoError(t, err)
	require.Len(t, ciphertexts, sympasta2.Pasta4Param1614.BlockSize)
	require.Len(t, got, len(nonces))
	require.Len(t, got[0], sympasta2.Pasta4Param1614.BlockSize)
}

func TestPasta2HalfBootSpecBuildsParameters(t *testing.T) {
	spec := DefaultPasta2Config(Pasta2_4_1614, sympasta2.Pasta4Param1614).halfBootSpec()
	_, err := spec.ResidualParameters()
	require.NoError(t, err)
	require.Equal(t, spec.LogSlots, *spec.BootstrappingLiteral().LogSlots)
}
