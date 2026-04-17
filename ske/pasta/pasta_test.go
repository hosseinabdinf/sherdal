package pasta

import (
	"crypto/rand"
	"reflect"
	"sherdal/ske"
	"sherdal/utils"
	"testing"
)

func TestPasta3(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta3TestVector {
		// generate symmetric key
		var key ske.Key
		t.Run("PastaSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		symPasta := NewPasta(key, tc.Params)
		encryptor := symPasta.NewEncryptor()
		numBlocks := 10
		maxSlot := tc.Params.GetBlockSize() * numBlocks

		var plaintext ske.Plaintext
		var decrypted ske.Plaintext
		var ciphertext ske.Ciphertext

		// generate random plaintext
		plaintext = make(ske.Plaintext, maxSlot)
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

		logger.PrintFormatted("TestPasta3: [Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]",
			tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		t.Run("TestPasta3", func(t *testing.T) {
			if reflect.DeepEqual(plaintext, decrypted) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
				t.Fail()
			}
		})
	}
}

func TestPasta4(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta4TestVector {
		// generate symmetric key
		var key ske.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})
		symPasta := NewPasta(key, tc.Params)
		encryptor := symPasta.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize() * 5

		var plaintext ske.Plaintext
		var decrypted ske.Plaintext
		var ciphertext ske.Ciphertext

		// generate random plaintext
		plaintext = make(ske.Plaintext, maxSlot)
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

		logger.PrintFormatted("TestPasta4: [Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]",
			tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)
		logger.PrintSummarizedVector("symKey", key, len(key))
		logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
		logger.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
		logger.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

		t.Run("TestPasta4", func(t *testing.T) {
			if reflect.DeepEqual(plaintext, decrypted) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
				t.Fail()
			}
		})
	}
}

func TestPastaEncryptDecryptPartialBlock(t *testing.T) {
	params := Pasta4Param3215
	key := GenerateSymKey(params)
	encryptor := NewPasta(key, params).NewEncryptor()

	plaintext := make(ske.Plaintext, params.GetBlockSize()+3)
	for i := range plaintext {
		plaintext[i] = utils.SampleZq(rand.Reader, params.GetModulus())
	}

	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 7}
	ciphertext := encryptor.EncryptWithNonce(plaintext, nonce)
	decrypted := encryptor.DecryptWithNonce(ciphertext, nonce)

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("partial-block round trip mismatch\nplaintext=%v\ndecrypted=%v", plaintext, decrypted)
	}
}
