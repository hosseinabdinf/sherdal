package simple

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sherdal/utils"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func TestBGVCipherExpansion(t *testing.T) {
	for _, tc := range BGVTestVector {
		testBGVCipherExpansion(t, tc)
	}
}

func testBGVCipherExpansion(t *testing.T, context BgvTestContext) {
	logger := utils.NewLogger(utils.DEBUG)
	params, err := bgv.NewParametersFromLiteral(context.paramsLiteral)
	utils.HandleError(err)
	// setup
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)
	decryptor := bgv.NewDecryptor(params, sk)
	// for BGV the scale invariant is false
	evaluator := bgv.NewEvaluator(params, evk, false)

	// generate the data
	maxSlot := params.MaxSlots()
	data := make([]uint64, maxSlot)
	for i := 0; i < maxSlot; i++ {
		data[i] = sampling.RandUint64() % params.PlaintextModulus()
	}

	// encode the data
	var plaintext = bgv.NewPlaintext(params, params.MaxLevel())
	err = encoder.Encode(data, plaintext)

	// encrypt the data
	var ciphertext *rlwe.Ciphertext
	ciphertext, err = encryptor.EncryptNew(plaintext)
	utils.HandleError(err)

	// Evaluation data + data
	cDoubleData, err := evaluator.AddNew(ciphertext, ciphertext)
	utils.HandleError(err)

	// Decrypt
	plainDD := make([]uint64, len(data))
	doubleData := decryptor.DecryptNew(cDoubleData)
	err = encoder.Decode(doubleData, plainDD)
	utils.HandleError(err)

	logger.PrintFormatted("\n --- BGV TEST :: LogN:%d, logP:%d, MaxSlots:%d ---", params.LogN(), params.PlaintextModulus(), params.MaxSlots())
	logger.PrintSummarizedVector("Data", data, 10)
	logger.PrintSummarizedVector("DoubleData", plainDD, 10)

	// data to byte
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, data)
	utils.HandleError(err)
	p := buf.Bytes()
	PrintDataSize("Data", p)

	bParams, err := params.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("Params", bParams)

	bSK, err := sk.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("SK", bSK)

	bPK, err := pk.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("PK", bPK)

	bRLK, err := rlk.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("RLK", bRLK)

	bEVK, err := evk.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("EVK", bEVK)

	bCipher, err := ciphertext.MarshalBinary()
	utils.HandleError(err)
	PrintDataSize("Ciphertext", bCipher)
}

func PrintDataSize(label string, data []byte) {
	fmt.Printf("[*] %s Byte size: %d Kbytes ", label, len(data)/1024)
	fmt.Printf(" -- Bit size: %d Kbits \t[*]\n", (len(data)*8)/1024)
}
