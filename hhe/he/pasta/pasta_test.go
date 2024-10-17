package pasta

import (
	"encoding/binary"
	"fmt"
	"reflect"
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

	//lg.PrintDataLen(tc.Key)

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePasta.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	hePasta.CreateGaloisKeys(len(tc.ExCiphertext))
	lg.PrintMemUsage("CreateGaloisKeys")

	//encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	fvCiphers := hePasta.Transcipher(nonce, tc.ExCiphertext)
	lg.PrintMemUsage("Transcipher")

	decrypted := hePasta.Decrypt(fvCiphers[0])
	lg.PrintMemUsage("Decrypt")

	lg.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.SymParams.Rounds, tc.SymParams.Modulus, tc.SymParams.KeySize, tc.SymParams.BlockSize)
	lg.PrintSummarizedVector("symKey", tc.Key, len(tc.Key))
	//logger.PrintSummarizedVector("ciphertext", ciphertext, len(ciphertext))
	lg.PrintSummarizedVector("plaintext", tc.Plaintext, len(tc.Plaintext))
	lg.PrintSummarizedVector("decrypted", decrypted, len(decrypted))

	if reflect.DeepEqual(tc.Plaintext, decrypted) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
	}
}
