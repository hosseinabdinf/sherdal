package simple

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func BenchmarkBFV(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tc := range BFVTestVector {
			benchmarkBFV(&tc, b)
		}
	}
}

func benchmarkBFV(context *BfvTestContext, b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	logger := utils.NewLogger(utils.DEBUG)
	params, err := bgv.NewParametersFromLiteral(context.paramsLiteral)
	utils.HandleError(err)
	logger.PrintFormatted("\n --- BFV TEST :: LogN:%d, logP:%d, MaxSlots:%d ---",
		params.LogN(), params.PlaintextModulus(), params.MaxSlots())

	// setup
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)
	decryptor := bgv.NewDecryptor(params, sk)
	// for BFV the scale invariant is true
	evaluator := bgv.NewEvaluator(params, evk, true)

	// generate the data
	maxSlot := params.MaxSlots()
	data := make([]uint64, maxSlot)
	for i := 0; i < maxSlot; i++ {
		data[i] = sampling.RandUint64() % params.PlaintextModulus()
	}

	var plaintext *rlwe.Plaintext
	var ciphertext *rlwe.Ciphertext

	b.Run("BFV.Enc()", func(b *testing.B) {
		// encode the data
		plaintext = bgv.NewPlaintext(params, params.MaxLevel())
		err = encoder.Encode(data, plaintext)

		// encrypt the data
		ciphertext, err = encryptor.EncryptNew(plaintext)
		utils.HandleError(err)
	})

	var cDoubleData *rlwe.Ciphertext
	b.Run("BFV.Eval()", func(b *testing.B) {
		// Evaluation data + data
		cDoubleData, err = evaluator.AddNew(ciphertext, ciphertext)
		utils.HandleError(err)
	})

	var plainDD []uint64
	b.Run("BFV.Dec()", func(b *testing.B) {
		// Decrypt
		plainDD = make([]uint64, len(data))
		doubleData := decryptor.DecryptNew(cDoubleData)
		err = encoder.Decode(doubleData, plainDD)
		utils.HandleError(err)
	})

	//logger.PrintSummarizedVector("Data", data, 10)
	//logger.PrintSummarizedVector("DoubleData", plainDD, 10)
}
