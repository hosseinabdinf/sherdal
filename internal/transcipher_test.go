package internal

import (
	hera2 "sherdal/hhe/hera"
	rubato2 "sherdal/hhe/rubato"
	"sherdal/ske"
	"sherdal/ske/hera"
	"sherdal/ske/rubato"
	"testing"

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
