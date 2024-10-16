package rubato

import (
	"crypto/rand"
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func TestRubato(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestsVector {
		// generate symmetric key
		var key sym.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		symRubato := NewRubato(key, tc.Params)
		encryptor := symRubato.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize()

		var plaintext sym.Plaintext
		var decrypted sym.Plaintext
		var ciphertext sym.Ciphertext

		// generate random plaintext
		plaintext = make(sym.Plaintext, maxSlot)
		for i := 0; i < maxSlot; i++ {
			plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
		}

		t.Run("RubatoEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(plaintext)
			logger.PrintMemUsage("RubatoEncryptionTest")
		})

		t.Run("RubatoDecryptionTest", func(t *testing.T) {
			decrypted = encryptor.Decrypt(ciphertext)
			logger.PrintMemUsage("RubatoDecryptionTest")
		})

		logger.PrintFormatted("[BlockSize=%d | Modulus=%d | Rounds=%d | Sigma=%f]", tc.Params.BlockSize, tc.Params.Modulus, tc.Params.Rounds, tc.Params.Sigma)
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		precision, lost := encryptor.GetPrecisionAndLoss(plaintext, decrypted)
		logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)

		t.Run("RubatoTest", func(t *testing.T) {
			if precision > float64(95) {
				logger.PrintMessage("Got precision > 95%, it is working fine.")
			} else {
				logger.PrintMessage("Got precision < 95%, decryption failure!")
				t.Fail()
			}
		})
	}
}
