package pasta

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
	"testing"
)

func TestPasta3(t *testing.T) {
	//for _, tc := range pasta3TestVector {
	//	testHEPasta(t, tc)
	//}
	testHEPasta(t, pasta3TestVector[0])
}

func TestPasta4(t *testing.T) {
	//for _, tc := range pasta4TestVector {
	//	testHEPasta(t, tc)
	//}
	testHEPasta(t, pasta4TestVector[0])
}

func testHEPasta(t *testing.T, tc TestContext) {
	hePasta := NewHEPasta()
	lg := hePasta.logger

	// Symmetric Pasta
	var symKey sym.Key
	symKey = pasta.GenerateSymKey(tc.SymParams)
	lg.PrintMemUsage("SymKeyGen")

	symPasta := pasta.NewPasta(symKey, tc.SymParams)
	encryptor := symPasta.NewEncryptor()
	numBlocks := 1
	maxSlot := tc.SymParams.GetBlockSize() * numBlocks

	var plaintext sym.Plaintext
	var ciphertext sym.Ciphertext

	// generate random plaintext
	plaintext = make(sym.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZq(rand.Reader, tc.SymParams.GetModulus())
	}

	ciphertext = encryptor.Encrypt(plaintext)
	lg.PrintMemUsage("PastaEncryptionTest")

	// HE Pasta
	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePasta.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	hePasta.CreateGaloisKeys(len(ciphertext))
	lg.PrintMemUsage("CreateGaloisKeys")

	//encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(symKey)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	fvCiphers := hePasta.Transcipher(nonce, ciphertext)
	lg.PrintMemUsage("Transcipher")

	decrypted := hePasta.Decrypt(fvCiphers[0])
	lg.PrintMemUsage("Decrypt")

	lg.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.SymParams.Rounds, tc.SymParams.Modulus, tc.SymParams.KeySize, tc.SymParams.BlockSize)
	lg.PrintSummarizedVector("symKey", symKey, len(symKey))
	//logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
	lg.PrintSummarizedVector("plaintext", plaintext, len(plaintext))
	lg.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

	if reflect.DeepEqual(plaintext, decrypted) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
	}
}
