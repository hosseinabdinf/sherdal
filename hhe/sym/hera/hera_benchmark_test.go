package hera

import (
	"crypto/rand"
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func BenchmarkHera(b *testing.B) {
	for _, tc := range TestVector {
		benchmarkHera(&tc, b)
	}
}

func benchmarkHera(tc *TestContext, b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintFormatted("[BlockSize=%d | Modulus=%d | Rounds=%d]", tc.Params.GetBlockSize(), tc.Params.GetModulus(), tc.Params.GetRounds())
	// generate symmetric key
	var key sym.Key
	b.Run("HERA/SymGenKey", func(b *testing.B) {
		key = GenerateSymKey(tc.Params)
	})

	var heraCipher Hera
	var encryptor Encryptor
	var plaintext sym.Plaintext
	//var decrypted sym.Plaintext
	var ciphertext sym.Ciphertext

	b.Run("HERA/NewHera", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heraCipher = NewHera(key, tc.Params)
		}
	})

	b.Run("HERA/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = heraCipher.NewEncryptor()
		}
	})

	// generate random plaintext
	plaintext = make(sym.Plaintext, tc.Params.GetBlockSize())
	for i := 0; i < tc.Params.GetBlockSize(); i++ {
		plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
	}

	b.Run("HERA/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ciphertext = encryptor.Encrypt(plaintext)
		}
	})

	b.Run("HERA/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = encryptor.Decrypt(ciphertext)
		}
	})

}
