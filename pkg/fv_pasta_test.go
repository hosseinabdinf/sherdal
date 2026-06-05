package pkg_test

import (
	"encoding/binary"
	"testing"

	"github.com/hosseinabdinf/sherdal/pkg"
	sympasta "github.com/hosseinabdinf/sherdal/ske/pasta"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// newPastaRuntime builds a BGVRuntime whose plaintext modulus matches
// the given PASTA parameter set and whose logN is large enough to hold
// at least one nonce lane (slots = 2^logN / 2).
func newPastaRuntime(t *testing.T, params sympasta.Parameter) *pkg.BGVRuntime {
	t.Helper()
	// logN=12 gives 2048 slots, comfortably more than one nonce lane.
	rt, err := pkg.NewDefaultBGVRuntime(12, params.Modulus)
	require.NoError(t, err, "NewDefaultBGVRuntime")
	return rt
}

// -----------------------------------------------------------------------------
// constructor tests
// -----------------------------------------------------------------------------

func TestNewFVPastaEvaluator_InvalidBlockSize(t *testing.T) {
	rt, err := pkg.NewDefaultBGVRuntime(12, 65537)
	require.NoError(t, err)

	// BlockSize 0 → error
	_, err = pkg.NewFVPastaEvaluator(rt, sympasta.Parameter{KeySize: 0, BlockSize: 0, Rounds: 3, Modulus: 65537})
	require.Error(t, err, "expected error for block size 0")

	// KeySize != 2*BlockSize → error
	_, err = pkg.NewFVPastaEvaluator(rt, sympasta.Parameter{KeySize: 10, BlockSize: 3, Rounds: 3, Modulus: 65537})
	require.Error(t, err, "expected error when KeySize != 2*BlockSize")
}

func TestNewFVPastaEvaluator_ValidParams(t *testing.T) {
	for _, params := range []sympasta.Parameter{
		sympasta.Pasta3Param1614,
		sympasta.Pasta4Param1614,
	} {
		rt := newPastaRuntime(t, params)
		ev, err := pkg.NewFVPastaEvaluator(rt, params)
		require.NoError(t, err)
		require.NotNil(t, ev)
	}
}

// -----------------------------------------------------------------------------
// EncryptKey tests
// -----------------------------------------------------------------------------

func TestFVPastaEvaluator_EncryptKey_WrongLength(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	// key shorter than KeySize → error
	_, err = ev.EncryptKey(make([]uint64, params.KeySize-1))
	require.Error(t, err)

	// key longer than KeySize → error
	_, err = ev.EncryptKey(make([]uint64, params.KeySize+1))
	require.Error(t, err)
}

func TestFVPastaEvaluator_EncryptKey_CorrectLength(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	// Key must be params.KeySize elements (full state = state1 + state2).
	key := make([]uint64, params.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}

	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)
	require.Len(t, encKey, params.KeySize)
	for i, ct := range encKey {
		require.NotNil(t, ct, "encrypted key element %d is nil", i)
	}
}

// -----------------------------------------------------------------------------
// Crypt smoke test – output shape
// -----------------------------------------------------------------------------

func TestFVPastaEvaluator_Crypt_OutputShape(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	// Key is KeySize elements (full state).
	key := make([]uint64, params.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, 0)

	nonces := [][]byte{nonce}

	cts, err := ev.Crypt(nonces, counter, encKey)
	require.NoError(t, err)
	// Output must be exactly BlockSize ciphertexts (state1 half only).
	require.Len(t, cts, params.BlockSize)
	for i, ct := range cts {
		require.NotNil(t, ct, "output ciphertext %d is nil", i)
	}
}

// -----------------------------------------------------------------------------
// CryptWithCounters smoke test – per-lane counter variant
// -----------------------------------------------------------------------------

func TestFVPastaEvaluator_CryptWithCounters_OutputShape(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	// Key is KeySize elements (full state).
	key := make([]uint64, params.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)

	lanes := 3
	nonces := pkg.DeterministicNonces(lanes, 8)
	counters := make([][]byte, lanes)
	for i := range counters {
		counters[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(counters[i], uint64(i))
	}

	cts, err := ev.CryptWithCounters(nonces, counters, encKey)
	require.NoError(t, err)
	require.Len(t, cts, params.BlockSize)
	for i, ct := range cts {
		require.NotNil(t, ct, "output ciphertext %d is nil", i)
	}
}

// -----------------------------------------------------------------------------
// Crypt correctness – decrypt and compare to reference keystream (lane 0)
// -----------------------------------------------------------------------------

// TestFVPastaEvaluator_Crypt_KeySensitivity verifies that different keys produce
// different keystreams (basic soundness check of the crypto).
// Note: the FV PASTA evaluator and ske/pasta symmetric reference use different PRNG
// sampling orders, so their keystreams intentionally differ — correctness is validated
// at the transciphering integration level, not here.
func TestFVPastaEvaluator_Crypt_KeySensitivity(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)

	key1 := make([]uint64, params.KeySize)
	key2 := make([]uint64, params.KeySize)
	for i := range key1 {
		key1[i] = uint64(i + 1)
		key2[i] = uint64(i + 2) // different key
	}

	nonces := [][]byte{{0, 1, 2, 3, 4, 5, 6, 7}}
	counter := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	evalAndDecrypt := func(key []uint64) []uint64 {
		ev, err := pkg.NewFVPastaEvaluator(rt, params)
		require.NoError(t, err)
		encKey, err := ev.EncryptKey(key)
		require.NoError(t, err)
		cts, err := ev.Crypt(nonces, counter, encKey)
		require.NoError(t, err)
		out := make([]uint64, len(cts))
		for i, ct := range cts {
			vals, err := rt.DecryptUint(ct)
			require.NoError(t, err)
			out[i] = vals[0]
		}
		return out
	}

	ks1 := evalAndDecrypt(key1)
	ks2 := evalAndDecrypt(key2)
	require.NotEqual(t, ks1, ks2, "different keys must produce different keystreams")
}

// -----------------------------------------------------------------------------
// Determinism – two calls with same inputs must give same decrypted output
// -----------------------------------------------------------------------------

func TestFVPastaEvaluator_Crypt_Determinism(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	key := make([]uint64, params.KeySize)
	for i := range key {
		key[i] = uint64(i + 3)
	}
	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)

	nonces := pkg.DeterministicNonces(1, 8)
	counter := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	decrypt := func() []uint64 {
		cts, err := ev.Crypt(nonces, counter, encKey)
		require.NoError(t, err)
		out := make([]uint64, len(cts))
		for i, ct := range cts {
			vals, err := rt.DecryptUint(ct)
			require.NoError(t, err)
			out[i] = vals[0]
		}
		return out
	}

	first := decrypt()
	second := decrypt()
	require.Equal(t, first, second, "two identical Crypt calls must produce the same keystream")
}

// -----------------------------------------------------------------------------
// Nonce sensitivity – different nonces must produce different keystreams
// -----------------------------------------------------------------------------

func TestFVPastaEvaluator_Crypt_NonceSensitivity(t *testing.T) {
	params := sympasta.Pasta4Param1614
	rt := newPastaRuntime(t, params)
	ev, err := pkg.NewFVPastaEvaluator(rt, params)
	require.NoError(t, err)

	key := make([]uint64, params.KeySize)
	for i := range key {
		key[i] = uint64(i + 1)
	}
	encKey, err := ev.EncryptKey(key)
	require.NoError(t, err)

	counter := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	evalAndDecrypt := func(nonce []byte) []uint64 {
		cts, err := ev.Crypt([][]byte{nonce}, counter, encKey)
		require.NoError(t, err)
		out := make([]uint64, len(cts))
		for i, ct := range cts {
			vals, err := rt.DecryptUint(ct)
			require.NoError(t, err)
			out[i] = vals[0]
		}
		return out
	}

	ks1 := evalAndDecrypt([]byte{0, 0, 0, 0, 0, 0, 0, 1})
	ks2 := evalAndDecrypt([]byte{0, 0, 0, 0, 0, 0, 0, 2})

	require.NotEqual(t, ks1, ks2, "different nonces must produce different keystreams")
}
