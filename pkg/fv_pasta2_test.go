package pkg_test

import (
	"reflect"
	"testing"

	"github.com/hosseinabdinf/sherdal/pkg"
	sym "github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/ske/pasta2"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func testFVPasta2Params() pasta2.Parameter {
	return pasta2.Parameter{Rounds: 2, KeySize: 4, BlockSize: 2, Modulus: 65537}
}

func pasta2TestKey(params pasta2.Parameter) sym.Key {
	key := make(sym.Key, params.GetKeySize())
	for i := range key {
		key[i] = uint64((i*13 + 7) % int(params.GetModulus()))
	}
	return key
}

func newTestFVPasta2(t *testing.T, params pasta2.Parameter) (*pkg.BGVRuntime, *pkg.FVPasta2Evaluator) {
	t.Helper()

	runtime, err := pkg.NewDefaultBGVRuntime(15, params.GetModulus())
	require.NoError(t, err)

	evaluator, err := pkg.NewFVPasta2Evaluator(runtime, params)
	require.NoError(t, err)

	return runtime, evaluator
}

// -----------------------------------------------------------------------------
// constructor tests
// -----------------------------------------------------------------------------

func TestNewFVPasta2Evaluator_InvalidBlockSize(t *testing.T) {
	rt, err := pkg.NewDefaultBGVRuntime(12, 65537)
	require.NoError(t, err)

	// BlockSize 0 → error
	_, err = pkg.NewFVPasta2Evaluator(rt, pasta2.Parameter{KeySize: 0, BlockSize: 0, Rounds: 3, Modulus: 65537})
	require.Error(t, err)

	// KeySize != 2*BlockSize → error
	_, err = pkg.NewFVPasta2Evaluator(rt, pasta2.Parameter{KeySize: 10, BlockSize: 3, Rounds: 3, Modulus: 65537})
	require.Error(t, err)
}

func TestNewFVPasta2Evaluator_ValidParams(t *testing.T) {
	for _, params := range []pasta2.Parameter{
		pasta2.Pasta3Param1614,
		pasta2.Pasta4Param1614,
	} {
		runtime, err := pkg.NewDefaultBGVRuntime(15, params.GetModulus())
		require.NoError(t, err)
		ev, err := pkg.NewFVPasta2Evaluator(runtime, params)
		require.NoError(t, err)
		require.NotNil(t, ev)
	}
}

// -----------------------------------------------------------------------------
// EncryptKey tests
// -----------------------------------------------------------------------------

func TestFVPasta2Evaluator_EncryptKey_WrongLength(t *testing.T) {
	params := pasta2.Pasta4Param1614
	runtime, err := pkg.NewDefaultBGVRuntime(15, params.GetModulus())
	require.NoError(t, err)
	ev, err := pkg.NewFVPasta2Evaluator(runtime, params)
	require.NoError(t, err)

	_, err = ev.EncryptKey(make([]uint64, params.GetKeySize()-1))
	require.Error(t, err)

	_, err = ev.EncryptKey(make([]uint64, params.GetKeySize()+1))
	require.Error(t, err)
}

func TestFVPasta2Evaluator_EncryptKey_CorrectLength(t *testing.T) {
	params := pasta2.Pasta4Param1614
	runtime, err := pkg.NewDefaultBGVRuntime(15, params.GetModulus())
	require.NoError(t, err)
	ev, err := pkg.NewFVPasta2Evaluator(runtime, params)
	require.NoError(t, err)

	key := make([]uint64, params.GetKeySize())
	for i := range key {
		key[i] = uint64(i + 1)
	}

	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)
	require.Len(t, encKey, params.GetKeySize())
	for i, ct := range encKey {
		require.NotNil(t, ct, "encrypted key element %d is nil", i)
	}
}

// -----------------------------------------------------------------------------
// Crypt correctness & trace tests
// -----------------------------------------------------------------------------

func TestFVPasta2CryptMatchesPlainKeystream(t *testing.T) {
	params := testFVPasta2Params()
	runtime, evaluator := newTestFVPasta2(t, params)

	evaluator.SetNoiseEstimator(pkg.NewBGVResidualNoiseEstimator(runtime))

	key := pasta2TestKey(params)
	encryptedKey, err := evaluator.EncryptKey(key)
	require.NoError(t, err)

	seeds := [][]byte{
		pasta2.NonceCounterSeed([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0),
		pasta2.NonceCounterSeed([]byte{8, 7, 6, 5, 4, 3, 2, 1}, 3),
	}
	encryptedKeystream, trace, err := evaluator.CryptWithTrace(seeds, encryptedKey)
	require.NoError(t, err)
	require.Len(t, trace, params.GetRounds())

	require.Equal(t, "S_feistel", trace[0].Layer)
	require.Equal(t, 1, trace[0].Round)
	require.Equal(t, "S_cube", trace[1].Layer)
	require.Equal(t, params.GetRounds(), trace[1].Round)

	for _, record := range trace {
		require.Equal(t, params.GetKeySize(), record.Coordinates)
		require.True(t, record.MinLevel <= record.MaxLevel)
		require.NotNil(t, record.Noise)
		record.Print()
	}

	got, err := runtime.DecryptOutputs(encryptedKeystream, len(seeds))
	require.NoError(t, err)

	plain := pasta2.NewPasta2(key, params)
	want := [][]uint64{
		plain.KeyStream(seeds[0][:sym.NonceSize], seeds[0][sym.NonceSize:]),
		plain.KeyStream(seeds[1][:sym.NonceSize], seeds[1][sym.NonceSize:]),
	}
	require.True(t, reflect.DeepEqual(got, want))
}

func TestFVPasta2DecryptSymmetricBlocks(t *testing.T) {
	params := testFVPasta2Params()
	runtime, evaluator := newTestFVPasta2(t, params)

	key := pasta2TestKey(params)
	encryptedKey, err := evaluator.EncryptKey(key)
	require.NoError(t, err)

	nonce := []byte{11, 12, 13, 14, 15, 16, 17, 18}
	plaintext := sym.Plaintext{1, 2}
	ciphertext := pasta2.NewPasta2(key, params).NewEncryptor().EncryptWithNonce(plaintext, nonce)
	decrypted, err := evaluator.DecryptSymmetricBlocks(
		[][]byte{pasta2.NonceCounterSeed(nonce, 0)},
		encryptedKey,
		[][]uint64{ciphertext},
	)
	require.NoError(t, err)

	got, err := runtime.DecryptOutputs(decrypted[:len(plaintext)], 1)
	require.NoError(t, err)
	require.Equal(t, []uint64(plaintext), got[0])
}
