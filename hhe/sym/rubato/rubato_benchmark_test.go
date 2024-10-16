package rubato

import (
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func BenchmarkRubato(b *testing.B) {
	for _, tc := range TestsVector {
		benchmarkRubato(&tc, b)
	}
}

func benchmarkRubato(tc *TestContext, b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintFormatted("[BlockSize=%d | Modulus=%d | Rounds=%d | Sigma=%f]", tc.Params.BlockSize, tc.Params.Modulus, tc.Params.Rounds, tc.Params.Sigma)
	var rubatoCipher Rubato
	var encryptor Encryptor
	var newCiphertext sym.Ciphertext

	b.Run("Rubato/NewRubato", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rubatoCipher = NewRubato(tc.Key, tc.Params)
		}
	})

	b.Run("Rubato/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = rubatoCipher.NewEncryptor()
		}
	})

	b.Run("Rubato/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			newCiphertext = encryptor.Encrypt(tc.Plaintext)
		}
	})

	b.Run("Rubato/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(newCiphertext)
		}
	})
}
