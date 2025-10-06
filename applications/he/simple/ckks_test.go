package simple

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sherdal/utils"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func TestCKKSCipherExpansion(t *testing.T) {
	for _, tc := range CKKSTestVector {
		testCKKSCipherExpansion(t, tc)
	}
}

func testCKKSCipherExpansion(t *testing.T, context CKKSTestContext) {
	logger := utils.NewLogger(utils.DEBUG)
	params, err := ckks.NewParametersFromLiteral(context.paramsLiteral)
	utils.HandleError(err)
	// setup
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	evaluator := ckks.NewEvaluator(params, evk)

	// generate the data
	maxSlot := params.MaxSlots()
	data := make([]float64, maxSlot)
	for i := 0; i < maxSlot; i++ {
		data[i] = sampling.RandFloat64(-50, 50)
	}

	// encode the data
	var plaintext = ckks.NewPlaintext(params, params.MaxLevel())
	err = encoder.Encode(data, plaintext)

	// encrypt the data
	var ciphertext *rlwe.Ciphertext
	ciphertext, err = encryptor.EncryptNew(plaintext)
	utils.HandleError(err)

	// Evaluation data + data
	cDoubleData, err := evaluator.AddNew(ciphertext, ciphertext)
	utils.HandleError(err)

	// Decrypt
	plainDD := make([]float64, len(data))
	doubleData := decryptor.DecryptNew(cDoubleData)
	err = encoder.Decode(doubleData, plainDD)
	utils.HandleError(err)

	logger.PrintFormatted("\n --- CKKS TEST :: LogN:%d, logP:%d, MaxSlots:%d ---", params.LogN(), params.LogP(), params.MaxSlots())
	fmt.Println("Data", data[:10])
	fmt.Println("DoubleData", plainDD[:10])

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
