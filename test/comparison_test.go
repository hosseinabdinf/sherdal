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
	N := 8 //max is N
	//Modulus := uint64(65929217)
	//modulus := uint64(65929216)
	// Parameters (128 bit security) with plaintext modulus 65929217
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65929217
	params, err := bgv.NewParametersFromLiteral(bgv.ExampleParameters128BitLogN14LogQP438)
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
	galoisKeys := kgen.GenGaloisKeysNew([]uint64{5}, Sk)
	relinKey := kgen.GenRelinearizationKeyNew(Sk)
	evKeySet := rlwe.NewMemEvaluationKeySet(relinKey, galoisKeys...)
	evaluator := bgv.NewEvaluator(params, evKeySet)

	prng, _ := sampling.NewPRNG()

	maxvalue := uint64(math.Sqrt(float64(params.PlaintextModulus()))) // max values = floor(sqrt(plaintext modulus))
	mask := uint64(1<<bits.Len64(maxvalue) - 1)                       // binary mask upper-bound for the uniform sampling

	//randValue := ring.RandUniform(prng, maxvalue, mask)
	//randValue2 := ring.RandUniform(prng, maxvalue, mask)
	ones := []uint64{1, 1, 1, 1, 1, 1, 1, 1}
	plainData1 := []uint64{0, 0, 1, 0, 0, 1, 0, 0}
	plainData2 := []uint64{0, 0, 1, 0, 0, 1, 0, 1}
	mainData := []uint64{ring.RandUniform(prng, maxvalue, mask)}
	/*for i := 0; i < N; i++ {
		plainData[i] = 1
		plainData2[i] = 1
	}*/

	onesPlain := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(ones, onesPlain); err != nil {
		panic(err)
	}

	Plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(plainData1, Plaintext); err != nil {
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
	cipherOnes, _ := encryptorSk.EncryptNew(onesPlain)

	mainDataCipher, _ := encryptorSk.EncryptNew(MainPlainText)
	cipherQuery, err := evaluator.SubNew(cipher, cipher2)
	if err != nil {
		panic(err)
	}
	// Get rid of pesky "-1"
	evaluator.MulRelin(cipherQuery, cipherQuery, cipherQuery)

	err = evaluator.Sub(cipherOnes, cipherQuery, cipherQuery)

	rotator := bgv.NewCiphertext(params, cipherQuery.Degree(), cipherQuery.Level())
	evaluator.Add(rotator, cipherQuery, rotator)
	newQuery := bgv.NewCiphertext(params, rotator.Degree(), rotator.Level())
	evaluator.Add(newQuery, cipherQuery, newQuery)

	rotatorPlain := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(rotator), rotatorPlain)
	log.Print("rotator start: ", rotatorPlain)

	newQueryPlain := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(newQuery), newQueryPlain)
	log.Print("new query start: ", newQueryPlain)
	for i := 0; i < N-1; i++ {
		if err := evaluator.RotateColumns(rotator, 1, rotator); err != nil {
			panic(err)
		} else {
			rotatorPlain := make([]uint64, N)
			encoder.Decode(decryptor.DecryptNew(rotator), rotatorPlain)
			log.Print("rotator: ", rotatorPlain)

			evaluator.MatchScalesAndLevel(newQuery, rotator)

			err = evaluator.MulRelin(newQuery, rotator, newQuery)
			if err != nil {
				panic(err)
			}
			err = evaluator.Rescale(newQuery, newQuery)
			if err != nil {
				panic(err)
			}
			err = evaluator.Rescale(rotator, rotator)
			if err != nil {
				panic(err)
			}

			newQueryPlain := make([]uint64, N)
			encoder.Decode(decryptor.DecryptNew(newQuery), newQueryPlain)
			log.Print("newQuery: ", newQueryPlain)
		}
	}

	if err != nil {
		panic(err)
	}
	retrievedData, err := evaluator.MulRelinNew(newQuery, mainDataCipher)
	if err != nil {
		panic(err)
	}

	newQueryPlain = make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(newQuery), newQueryPlain)
	cipherQueryResult := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(cipherQuery), cipherQueryResult)
	result := make([]uint64, N)
	encoder.Decode(decryptor.DecryptNew(retrievedData), result)

	for i := range mainData {
		log.Print("PlainData1: ", plainData1, " PlainData2: ", plainData2, " p1 ==: ", newQueryPlain[i], " MainPlainData: ", mainData[i], " Result: ", result[i])
	}
}
