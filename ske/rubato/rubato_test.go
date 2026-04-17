package rubato

import (
	"crypto/rand"
	"math"
	"reflect"
	"sherdal/ske"
	"sherdal/utils"
	"testing"
)

func TestRubato(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestsVector {
		// generate symmetric key
		var key ske.Key
		t.Run("RubatoSymKeyGen", func(t *testing.T) {
			key = GenerateSymKey(tc.Params)
		})

		symRubato := NewRubato(key, tc.Params)
		encryptor := symRubato.NewEncryptor()
		maxSlot := tc.Params.GetBlockSize()

		var plaintext ske.Plaintext
		var decrypted ske.Plaintext
		var ciphertext ske.Ciphertext

		// generate random plaintext
		plaintext = make(ske.Plaintext, maxSlot)
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

func TestRubatoEncryptDecryptPartialBlock(t *testing.T) {
	params := Rubato5Param2616
	params.Sigma = 0

	key := GenerateSymKey(params)
	encryptor := NewRubato(key, params).NewEncryptor()

	payloadSize := params.GetBlockSize() - 4
	plaintext := make(ske.Plaintext, payloadSize+3)
	for i := range plaintext {
		plaintext[i] = utils.SampleZq(rand.Reader, params.GetModulus())
	}

	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 5}
	ciphertext := encryptor.EncryptWithNonce(plaintext, nonce)
	decrypted := encryptor.DecryptWithNonce(ciphertext, nonce)

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("partial-block round trip mismatch\nplaintext=%v\ndecrypted=%v", plaintext, decrypted)
	}
}

func TestRubatoPrecisionHandlesZeroPlaintext(t *testing.T) {
	params := Rubato5Param2616
	encryptor := NewRubato(GenerateSymKey(params), params).NewEncryptor()

	precision, loss := encryptor.GetPrecisionAndLoss([]uint64{0, 0, 0, 0, 0, 0, 10}, []uint64{0, 0, 0, 0, 0, 0, 9})
	if math.IsNaN(precision) || math.IsInf(precision, 0) {
		t.Fatalf("precision should be finite, got %v", precision)
	}
	if math.IsNaN(loss) || math.IsInf(loss, 0) {
		t.Fatalf("loss should be finite, got %v", loss)
	}
}
