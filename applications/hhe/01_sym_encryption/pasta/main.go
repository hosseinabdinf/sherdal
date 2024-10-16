// This is a sample application for encryption a vector of random numbers using
// hybrid homomorphic encryption scheme: PASTA
package main

import (
	"crypto/rand"
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Simple Symmetric Encryption Application")

	// select the symmetric parameter set
	symParams := pasta.Pasta3Param1614
	numBlocks := 100
	maxSlot := symParams.GetBlockSize() * numBlocks

	// generate symmetric key
	symKey := pasta.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symPasta := pasta.NewPasta(symKey, symParams)
	symEnc := symPasta.NewEncryptor()

	// generate a vector of random numbers
	plaintext := make(sym.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZqx(rand.Reader, symParams.GetModulus())
	}

	ciphertext := symEnc.Encrypt(plaintext)
	logger.PrintMemUsage("PastaEncryption")

	// decrypt image data using symmetric cipher
	newPlaintext := symEnc.Decrypt(ciphertext)
	logger.PrintMemUsage("PastaDecryption")

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
