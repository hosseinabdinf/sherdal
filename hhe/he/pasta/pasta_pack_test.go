package pasta

import (
	"encoding/binary"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/pasta"
	"testing"
)

func TestPasta3Pack(t *testing.T) {
	//for _, tc := range pasta3TestVector {
	//	testHEPastaPack(t, tc)
	//}
	testHEPastaPack(t, pasta3TestVector[0])
}

func TestPasta4Pack(t *testing.T) {
	//for _, tc := range pasta4TestVector {
	//	testHEPastaPack(t, tc)
	//}
	testHEPastaPack(t, pasta4TestVector[0])
}

func testHEPastaPack(t *testing.T, tc TestContext) {
	hePastaPack := NewHEPastaPack()
	lg := hePastaPack.logger

	// Symmetric Pasta
	var symKey sym.Key
	symKey = pasta.GenerateSymKey(tc.SymParams)

	// HE Pasta
	hePastaPack.InitParams(tc.Params, tc.SymParams)

	hePastaPack.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePastaPack.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	// generates Random data for full coefficients
	plaintext := hePastaPack.RandomDataGen()
	lg.PrintMemUsage("RandomDataGen")

	// generate key stream
	symPasta := pasta.NewPasta(symKey, tc.SymParams)
	symCiphertexts := symPasta.NewEncryptor().Encrypt(plaintext)
	lg.PrintMemUsage("EncryptSymData")

	// create Galois keys for evaluation
	hePastaPack.CreateGaloisKeys(len(symCiphertexts))
	lg.PrintMemUsage("CreateGaloisKeys")

	// encrypts symmetric master key using BFV on the client side
	hePastaPack.EncryptSymKey(symKey)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, 123456789)

	// the server side transciphering
	fvCiphers := hePastaPack.Transcipher(nonce, symCiphertexts)
	lg.PrintMemUsage("Transcipher")

	ctRes := hePastaPack.Flatten(fvCiphers, len(symCiphertexts))
	lg.PrintMemUsage("Flatten")

	decrypted := hePastaPack.Decrypt(ctRes)
	lg.PrintMemUsage("Decrypt")

	lg.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.SymParams.Rounds, tc.SymParams.Modulus, tc.SymParams.KeySize, tc.SymParams.BlockSize)
	lg.PrintSummarizedVector("symKey", symKey, len(symKey))
	//logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
	lg.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
	lg.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

	//hePastaPack.logger.PrintDataLen(plaintext)
	//hePastaPack.logger.PrintDataLen(decrypted)
}
