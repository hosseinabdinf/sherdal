package hera

import (
	"crypto/rand"
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func TestHera(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestVector {

		// generate symmetric key
		var key sym.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		// create a new HERA instance
		heraCipher := NewHera(key, tc.Params)
		encryptor := heraCipher.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize()

		var plaintext sym.Plaintext
		var decrypted sym.Plaintext
		var ciphertext sym.Ciphertext

		// generate random plaintext
		plaintext = make(sym.Plaintext, maxSlot)
		for i := 0; i < maxSlot; i++ {
			plaintext[i] = utils.SampleZqx(rand.Reader, tc.Params.GetModulus())
		}

		t.Run("HeraEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(plaintext)
			logger.PrintMemUsage("HeraEncryptionTest")
		})

		t.Run("HeraDecryptionTest", func(t *testing.T) {
			decrypted = encryptor.Decrypt(ciphertext)
			logger.PrintMemUsage("HeraDecryptionTest")
		})

		logger.PrintFormatted("[BlockSize=%d | Modulus=%d | Rounds=%d]", tc.Params.GetBlockSize(), tc.Params.GetModulus(), tc.Params.GetRounds())
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		t.Run("HeraTest", func(t *testing.T) {
			if reflect.DeepEqual(plaintext, decrypted) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
				t.Fail()
			}
		})
	}
}
