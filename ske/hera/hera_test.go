package hera

import (
	"crypto/rand"
	"reflect"
	"sherdal/ske"
	"sherdal/utils"
	"testing"
)

func TestHera(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestVector {

		// generate symmetric key
		var key ske.Key
		t.Run("HeraSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		// create a new HERA instance
		heraCipher := NewHera(key, tc.Params)
		encryptor := heraCipher.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize()

		var plaintext ske.Plaintext
		var decrypted ske.Plaintext
		var ciphertext ske.Ciphertext

		// generate random plaintext
		plaintext = make(ske.Plaintext, maxSlot)
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

func TestHeraEncryptDecryptPartialBlock(t *testing.T) {
	params := Hera5Params2816
	key := GenerateSymKey(params)
	encryptor := NewHera(key, params).NewEncryptor()

	plaintext := make(ske.Plaintext, params.GetBlockSize()+3)
	for i := range plaintext {
		plaintext[i] = utils.SampleZqx(rand.Reader, params.GetModulus())
	}

	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 11}
	ciphertext := encryptor.EncryptWithNonce(plaintext, nonce)
	decrypted := encryptor.DecryptWithNonce(ciphertext, nonce)

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("partial-block round trip mismatch\nplaintext=%v\ndecrypted=%v", plaintext, decrypted)
	}
}

func TestHeraEncryptorKeyStreamAllocatesRows(t *testing.T) {
	params := Hera4Params2816
	key := GenerateSymKey(params)
	encryptor := NewHera(key, params).NewEncryptor()

	keyStream := encryptor.KeyStreamWithNonce(params.GetBlockSize()+1, []byte{0, 0, 0, 0, 0, 0, 0, 3})
	if len(keyStream) != 2 {
		t.Fatalf("expected 2 keystream blocks, got %d", len(keyStream))
	}

	for i := range keyStream {
		if len(keyStream[i]) != params.GetBlockSize() {
			t.Fatalf("expected block %d to have size %d, got %d", i, params.GetBlockSize(), len(keyStream[i]))
		}
	}
}
