// This is a sample application for encryption a vector of random numbers using
// hybrid homomorphic encryption scheme: Rubato
package main

import (
	"crypto/rand"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/rubato"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Simple Symmetric Encryption Application")

	// select the symmetric parameter set
	symParams := rubato.Rubato5Param2616
	numBlocks := 100
	maxSlot := symParams.GetBlockSize() * numBlocks

	// generate symmetric key
	symKey := rubato.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symRubato := rubato.NewRubato(symKey, symParams)
	symEnc := symRubato.NewEncryptor()

	// generate a vector of random numbers
	plaintext := make(sym.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZqx(rand.Reader, symParams.GetModulus())
	}

	ciphertext := symEnc.Encrypt(plaintext)
	logger.PrintMemUsage("RubatoEncryption")

	// decrypt image data using symmetric cipher
	decrypted := symEnc.Decrypt(ciphertext)
	logger.PrintMemUsage("RubatoDecryption")

	logger.PrintSummarizedVector("key", symKey, len(symKey))
	logger.PrintSummarizedVector("ciphertext", ciphertext, maxSlot)
	// print a summary of the original and decrypted data for debug
	logger.PrintSummarizedVector("Original", plaintext, maxSlot)
	logger.PrintSummarizedVector("Decrypted", decrypted, maxSlot)

	precision, lost := symEnc.GetPrecisionAndLoss(plaintext, decrypted)
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)
}
