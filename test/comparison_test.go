package test

import (
	"flag"
	"log"
	"math"
	"math/bits"
	"sherdal/hhe/he/ckks_fv/ring"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	sampling "github.com/tuneinsight/lattigo/v6/utils/sampling"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func TestComparison(t *testing.T) {

	// Number of drivers in the area
	N := 2 //max is N

	// Parameters (128 bit security) with plaintext modulus 65929217
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65929217
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             20,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}

	encoder := bgv.NewEncoder(params)

	// Rider's keygen
	kgen := bgv.NewKeyGenerator(params)
	Sk, _ := kgen.GenKeyPairNew()
	decryptor := rlwe.NewDecryptor(params, Sk)
	//encryptorPk := rlwe.NewEncryptor(params, riderPk)
	encryptorSk := rlwe.NewEncryptor(params, Sk)

	relinKey := kgen.GenRelinearizationKeyNew(Sk)
	evKeySet := rlwe.NewMemEvaluationKeySet(relinKey)
	evaluator := bgv.NewEvaluator(params, evKeySet)

	prng, _ := sampling.NewPRNG()

	maxvalue := uint64(math.Sqrt(float64(params.PlaintextModulus()))) // max values = floor(sqrt(plaintext modulus))
	mask := uint64(1<<bits.Len64(maxvalue) - 1)                       // binary mask upper-bound for the uniform sampling

	//randValue := ring.RandUniform(prng, maxvalue, mask)
	//randValue2 := ring.RandUniform(prng, maxvalue, mask)
	plainData := make([]uint64, N)
	plainData2 := make([]uint64, N)
	mainData := make([]uint64, N)
	for i := 0; i < N; i++ {
		plainData[i] = 1
		plainData2[i] = 1
		mainData[i] = ring.RandUniform(prng, maxvalue, mask)
	}

	Plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(plainData, Plaintext); err != nil {
		panic(err)
	}

	Plaintext2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(plainData2, Plaintext2); err != nil {
		panic(err)
	}

	MainPlainText := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(mainData, MainPlainText); err != nil {
		panic(err)
	}

	cipher, _ := encryptorSk.EncryptNew(Plaintext)
	cipher2, _ := encryptorSk.EncryptNew(Plaintext2)
	mainDataCipher, _ := encryptorSk.EncryptNew(MainPlainText)
	cipherCombined, _ := evaluator.AddNew(cipher, -1)
	cipherQuery, err := evaluator.MulNew(cipherCombined, cipher2)
	if err != nil {
		panic(err)
	}

	err = evaluator.Relinearize(cipherQuery, cipherQuery)

	if err != nil {
		panic(err)
	}

	retrievedData, err := evaluator.MulNew(cipherQuery, mainDataCipher)
	if err != nil {
		panic(err)
	}

	cipherQueryResult := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(cipherQuery), cipherQueryResult)
	result := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(retrievedData), result)

	for i := range plainData {
		log.Print("PlainData1: ", plainData[i], " PlainData2: ", plainData2[i], " cipherQueryResult: ", cipherQueryResult[i], " MainPlainData: ", mainData[i], " Result: ", result[i])
	}
}
