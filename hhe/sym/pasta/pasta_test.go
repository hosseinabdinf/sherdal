package pasta

import (
	"crypto/rand"
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/utils"
	"testing"
)

func TestPasta3(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta3TestVector {
		// generate symmetric key
		var key sym.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		symPasta := NewPasta(key, tc.Params)
		encryptor := symPasta.NewEncryptor()
		numBlocks := 10
		maxSlot := tc.Params.GetBlockSize() * numBlocks

		var plaintext sym.Plaintext
		var decrypted sym.Plaintext
		var ciphertext sym.Ciphertext

		// generate random plaintext
		plaintext = make(sym.Plaintext, maxSlot)
		for i := 0; i < maxSlot; i++ {
			plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
		}

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(plaintext)
			logger.PrintMemUsage("Pasta3EncryptionTest")
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			decrypted = encryptor.Decrypt(ciphertext)
			logger.PrintMemUsage("Pasta3DecryptionTest")
		})

		logger.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		t.Run("PastaTest", func(t *testing.T) {
			if reflect.DeepEqual(plaintext, decrypted) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
				t.Fail()
			}
		})

		//t.Run("Test", func(t *testing.T) {
		//	newCiphertext := encryptor.Encrypt(plaintext)
		//	newPlaintext := encryptor.Decrypt(newCiphertext)
		//
		//	if reflect.DeepEqual(plaintext, newPlaintext) {
		//		logger.PrintMessage("Got the same plaintext, it is working fine.")
		//	} else {
		//		logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
		//		t.Fail()
		//	}
		//	if reflect.DeepEqual(tc.ExpCipherText, newCiphertext) {
		//		logger.PrintMessage("Got the same ciphertext, it is working fine.")
		//	} else {
		//		logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
		//		t.Fail()
		//	}
		//})
	}
}

func TestPasta4(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta4TestVector {
		// generate symmetric key
		var key sym.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})
		symPasta := NewPasta(key, tc.Params)
		encryptor := symPasta.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize() * 5

		var plaintext sym.Plaintext
		var decrypted sym.Plaintext
		var ciphertext sym.Ciphertext

		// generate random plaintext
		plaintext = make(sym.Plaintext, maxSlot)
		for i := 0; i < maxSlot; i++ {
			plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
		}

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(plaintext)
			logger.PrintMemUsage("Pasta4EncryptionTest")
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			decrypted = encryptor.Decrypt(ciphertext)
		})

		logger.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		t.Run("PastaTest", func(t *testing.T) {
			if reflect.DeepEqual(plaintext, decrypted) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
				t.Fail()
			}
		})

		//t.Run("test", func(t *testing.T) {
		//	newCiphertext := encryptor.Encrypt(plaintext)
		//	newPlaintext := encryptor.Decrypt(newCiphertext)
		//
		//	if reflect.DeepEqual(plaintext, newPlaintext) {
		//		logger.PrintMessage("Got the same plaintext, it is working fine.")
		//	} else {
		//		logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
		//		t.Fail()
		//	}
		//	if reflect.DeepEqual(tc.ExpCipherText, newCiphertext) {
		//		logger.PrintMessage("Got the same ciphertext, it is working fine.")
		//	} else {
		//		logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
		//		t.Fail()
		//	}
		//})
	}
}
