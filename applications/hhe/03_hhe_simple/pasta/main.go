// Simple Hybrid Homomorphic Encryption using Pasta
package main

import (
	"crypto/rand"
	"encoding/binary"
	"sherdal/hhe"
	homPas "sherdal/hhe/he/pasta"
	symPas "sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Simple PASTA HHE Application")

	// select the parameter set, both must be from the same set
	symParams := hhe.HHEPasta3P1614.SymParams
	homParams := hhe.HHEPasta3P1614.HomParams

	// generate a vector of 100 random numbers
	vectorSize := 100
	data := make([]uint64, vectorSize)
	for i := 0; i < vectorSize; i++ {
		data[i] = utils.SampleZqx(rand.Reader, symParams.GetModulus())
	}

	// client
	logger.PrintMessage("Client Setup")

	// generate symmetric key
	symKey := symPas.GenerateSymKey(symParams)
	enc := symPas.NewPasta(symKey, symParams).NewEncryptor()
	ciphertext := enc.Encrypt(data)

	homPasta := homPas.NewHEPasta()
	homPasta.InitParams(homParams, symParams)
	homPasta.HEKeyGen()
	homPasta.InitFvPasta()
	homPasta.CreateGaloisKeys(len(ciphertext))

	homPasta.EncryptSymKey(symKey)

	// server
	logger.PrintMessage("Analyst Setup")
	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	fvCiphers := homPasta.Transcipher(nonce, ciphertext)

	// client
	decrypted := homPasta.Decrypt(fvCiphers[0])
	logger.PrintSummarizedVector("Plaintext", data, len(data))
	logger.PrintSummarizedVector("Decrypted", decrypted, len(decrypted))
}
