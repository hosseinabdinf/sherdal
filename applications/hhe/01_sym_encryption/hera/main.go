// This is a sample application for encryption a vector of random numbers using
// hybrid homomorphic encryption scheme: HERA
package main

import (
	"crypto/rand"
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/hera"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Hera Simple Symmetric Encryption Application")

	// select the symmetric parameter set
	symParams := hera.Hera4Params2816
	numBlocks := 100
	maxSlot := symParams.GetBlockSize() * numBlocks

	// generate symmetric key
	symKey := hera.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symHera := hera.NewHera(symKey, symParams)
	symEnc := symHera.NewEncryptor()

	// generate a vector of random numbers
	plaintext := make(sym.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZqx(rand.Reader, symParams.GetModulus())
	}

	ciphertext := symEnc.Encrypt(plaintext)
	logger.PrintMemUsage("HeraEncryption")

	// decrypt image data using symmetric cipher
	newPlaintext := symEnc.Decrypt(ciphertext)
	logger.PrintMemUsage("HeraDecryption")

	logger.PrintSummarizedVector("key", symKey, len(symKey))
	logger.PrintSummarizedVector("ciphertext", ciphertext, maxSlot)
	// print a summary of the original and decrypted data for debug
	logger.PrintSummarizedVector("Original", plaintext, maxSlot)
	logger.PrintSummarizedVector("Decrypted", newPlaintext, maxSlot)

	if reflect.DeepEqual(plaintext, newPlaintext) {
		logger.PrintMessage("The plaintext after decryption is equal to the original data!")
	} else {
		logger.PrintMessage("The plaintext after decryption is different, decryption failure!")
	}
}
