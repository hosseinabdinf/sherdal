package pkg_test

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/hhe/pasta"
	rubato2 "github.com/hosseinabdinf/sherdal/hhe/rubato"
	"github.com/hosseinabdinf/sherdal/pkg"

	"github.com/hosseinabdinf/sherdal/ske/hera"
	sympasta "github.com/hosseinabdinf/sherdal/ske/pasta"

	hera2 "github.com/hosseinabdinf/sherdal/hhe/hera"

	"github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/stretchr/testify/require"
)

func TestRubatoTranscipherSymCiphertext(t *testing.T) {
	params := rubato.Parameter{LogN: 16, BlockSize: 16, Modulus: rubato.Rubato5Param2616.Modulus, Rounds: 2, Sigma: 0}
	heRubato, err := rubato2.NewRubato(rubato2.Config{Preset: rubato2.Rubato128S, BGVLogN: 14, SymmetricParams: params})
	require.NoError(t, err)

	key := []uint64{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16}
	require.NoError(t, heRubato.EncryptSymmetricKey(key))

	plaintext := ske.Plaintext{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	symCipher := rubato.NewRubato(key, params).NewEncryptor().EncryptWithNonce(plaintext, nonce)

	heCipher, err := heRubato.TranscipherSymCiphertext(symCipher, nonce)
	require.NoError(t, err)

	newPlain, err := heRubato.Decrypt(heCipher, len(plaintext))
	require.NoError(t, err)
	require.Equal(t, []uint64(plaintext), newPlain)
}

func TestHeraTranscipherSymCiphertext(t *testing.T) {
	heHera, err := hera2.NewHera(hera2.Config{Preset: hera2.Hera128AF, BGVLogN: 15, SymmetricParams: hera.Hera4Params2516})
	require.NoError(t, err)

	key := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	require.NoError(t, heHera.EncryptSymmetricKey(key))

	plaintext := ske.Plaintext{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte{10, 11, 12, 13, 14, 15, 16, 17}
	symCipher := hera.NewHera(key, hera.Hera4Params2516).NewEncryptor().EncryptWithNonce(plaintext, nonce)

	heCipher, err := heHera.TranscipherSymCiphertext(symCipher, nonce)
	require.NoError(t, err)

	newPlain, err := heHera.Decrypt(heCipher, len(plaintext))
	require.NoError(t, err)
	require.Equal(t, []uint64(plaintext), newPlain)
}

func TestPastaTranscipherSymCiphertext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pasta transcipher test in short mode")
	}
	hePasta, err := pasta.NewPastaWithConfig(
		pasta.Config{Preset: pasta.Pasta4_1614, BGVLogN: 14, SymmetricParams: sympasta.Pasta4Param1614},
		pkg.ParallelConfig{MaxWorkers: 4},
	)
	require.NoError(t, err)

	key := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	require.NoError(t, hePasta.EncryptSymmetricKey(key))

	plaintext := ske.Plaintext{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := []byte{10, 11, 12, 13, 14, 15, 16, 17}
	symCipher := sympasta.NewPasta(key, sympasta.Pasta4Param1614).NewEncryptor().EncryptWithNonce(plaintext, nonce)

	heCipher, err := hePasta.TranscipherSymCiphertext(symCipher, nonce)
	require.NoError(t, err)

	newPlain, err := hePasta.Decrypt(heCipher, len(plaintext))
	require.NoError(t, err)
	require.Equal(t, []uint64(plaintext), newPlain)
}
