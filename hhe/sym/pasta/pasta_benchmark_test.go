package pasta

import (
	"crypto/rand"
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func BenchmarkPasta3(b *testing.B) {
	for _, tc := range pasta3TestVector {
		benchmarkPasta(&tc, b)
	}
}

func BenchmarkPasta4(b *testing.B) {
	for _, tc := range pasta4TestVector {
		benchmarkPasta(&tc, b)
	}
}

func benchmarkPasta(tc *TestContext, b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)

	var encryptor Encryptor
	var key sym.Key
	var symPasta Pasta
	var plaintext sym.Plaintext
	var ciphertext sym.Ciphertext

	// generate symmetric key
	b.Run("HeraSymKeyGen", func(b *testing.B) {
		key = GenerateSymKey(tc.Params)
	})

	b.Run("Pasta/NewPasta", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			symPasta = NewPasta(key, tc.Params)
		}
	})

	b.Run("Pasta/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = symPasta.NewEncryptor()
		}
	})

	numBlocks := 10
	maxSlot := tc.Params.GetBlockSize() * numBlocks
	// generate random plaintext
	plaintext = make(sym.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
	}

	b.Run("Pasta/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ciphertext = encryptor.Encrypt(plaintext)
		}
	})

	b.Run("Pasta/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(ciphertext)
		}
	})

}
