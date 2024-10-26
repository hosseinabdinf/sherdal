package rubato

import (
	"encoding/binary"
	"fmt"
	"math"
	ckks "sherdal/hhe/he/ckks_fv"
	"sherdal/hhe/sym/rubato"
	"testing"
)

func testString(opName string, p rubato.Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
}

func TestRubato(t *testing.T) {
	for _, tc := range rubato.TestsVector {
		fmt.Println(testString("Rubato", tc.Params))
		testHERubato(t, tc)
	}
}

func testHERubato(t *testing.T, tc rubato.TestContext) {
	heRubato := NewHERubato()
	lg := heRubato.logger
	lg.PrintDataLen(tc.Key)

	heRubato.InitParams(tc.FVParamIndex, tc.Params, len(tc.Plaintext))

	heRubato.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	heRubato.HalfBootKeyGen()
	lg.PrintMemUsage("HalfBootKeyGen")

	heRubato.InitHalfBootstrapper()
	lg.PrintMemUsage("InitHalfBootstrapper")

	heRubato.InitEvaluator()
	lg.PrintMemUsage("InitEvaluator")

	heRubato.InitCoefficients()
	lg.PrintMemUsage("InitCoefficients")

	// use the plaintext data from test vector or generate Random ones for full coefficients
	data := heRubato.RandomDataGen()
	lg.PrintMemUsage("RandomDataGen")

	// need an array of 8-byte nonce for each block of data
	nonces := heRubato.NonceGen()

	// need an 8-byte counter
	counter := make([]byte, 8)

	// generate key stream using plain rubato
	keyStream := make([][]uint64, heRubato.params.N())
	for i := 0; i < heRubato.params.N(); i++ {
		symRub := rubato.NewRubato(tc.Key, tc.Params)
		binary.BigEndian.PutUint64(counter, uint64(i))
		keyStream[i] = symRub.KeyStream(nonces[i], counter)
	}
	lg.PrintMemUsage("SymKeyStreamGen")

	// data to coefficients
	heRubato.DataToCoefficients(data)
	lg.PrintMemUsage("DataToCoefficients")

	// simulate the data encryption on client side and encode the result into polynomial representations
	heRubato.EncodeEncrypt(keyStream)
	lg.PrintMemUsage("EncodeEncrypt")

	heRubato.ScaleUp()
	lg.PrintMemUsage("ScaleUp")

	_ = heRubato.InitFvRubato()
	lg.PrintMemUsage("InitFvRubato")

	// encrypts symmetric master key using BFV on the client side
	heRubato.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	fvKeyStreams := heRubato.GetFvKeyStreams(nonces, counter)
	lg.PrintMemUsage("GetFvKeyStreams")

	heRubato.ScaleCiphertext(fvKeyStreams)
	lg.PrintMemUsage("ScaleCiphertext")

	// half bootstrapping
	ctBoot := heRubato.HalfBoot()
	lg.PrintMemUsage("HalfBoot")

	valuesWant := make([]complex128, heRubato.params.Slots())
	for i := 0; i < heRubato.params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(heRubato.params, ctBoot, valuesWant,
		heRubato.ckksDecryptor, heRubato.ckksEncoder)
}

func printDebug(params *ckks.Parameters, ciphertext *ckks.Ciphertext,
	valuesWant []complex128, decryptor ckks.CKKSDecryptor, encoder ckks.CKKSEncoder) {

	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)

	fmt.Println(precStats.String())
}
