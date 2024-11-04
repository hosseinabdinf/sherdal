package main

import (
	"fmt"
	"sherdal/hhe/he/ckks_fv"
	"sherdal/hhe/he/rubato"
	symRub "sherdal/hhe/sym/rubato"
)

func main() {
	var kgen ckks_fv.KeyGenerator
	var fvEncoder ckks_fv.MFVEncoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.MFVEncryptor
	var fvDecryptor ckks_fv.MFVDecryptor
	var fvEvaluator ckks_fv.MFVEvaluator
	var fvNoiseEstimator ckks_fv.MFVNoiseEstimator
	var mfvRubato rubato.MFVRubato

	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var keystreamCt []*ckks_fv.Ciphertext

	blocksize := rubato.RubatoParams[rubato.RUBATO128L].Blocksize
	//numRound := rubato.RubatoParams[rubato.RUBATO128L].NumRound
	plainModulus := rubato.RubatoParams[rubato.RUBATO128L].PlainModulus
	//sigma := rubato.RubatoParams[rubato.RUBATO128L].Sigma

	hbtpParams := ckks_fv.RtFRubatoParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	params.SetPlainModulus(plainModulus)
	params.SetLogFVSlots(params.LogN())

	// Scheme context and keys
	fmt.Println("Key generation...")
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(192)

	fvEncoder = ckks_fv.NewMFVEncoder(params)
	fvEncryptor = ckks_fv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckks_fv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = ckks_fv.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	fvEvaluator = ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk}, nil)

	// Generating data set
	key = make([]uint64, blocksize)
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i + 1)
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 8)
		// rand.Read(nonces[i])
		for j := 0; j < 8; j++ {
			nonces[i][j] = byte(0)
		}
	}
	counter := make([]byte, 8)

	// Compute plain Rubato keystream
	fmt.Println("Computing plain keystream...")
	keystream = make([][]uint64, params.FVSlots())

	symParams := symRub.Rubato2Param2516
	symRubato := symRub.NewRubato(key, symParams)
	for i := 0; i < params.FVSlots(); i++ {
		//keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, plainModulus, sigma)
		keystream[i] = symRubato.KeyStream(nonces[i], counter)
	}

	// Evaluate the Rubato keystream
	fmt.Println("Evaluating HE keystream...")
	mfvRubato = rubato.NewMFVRubato(rubato.RUBATO128L, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	hekey := mfvRubato.EncKey(key)
	budget := fvNoiseEstimator.InvariantNoiseBudget(hekey[0])
	fmt.Printf("Initial noise budget: %d\n", budget)
	keystreamCt = mfvRubato.CryptNoModSwitch(nonces, counter, hekey)
	budget = fvNoiseEstimator.InvariantNoiseBudget(keystreamCt[0])
	fmt.Printf("Output noise budget: %d\n", budget)

	// Decrypt and decode the Rubato keystream
	for i := 0; i < blocksize-4; i++ {
		val := fvEncoder.DecodeUintSmallNew(fvDecryptor.DecryptNew(keystreamCt[i]))
		resString := fmt.Sprintf("keystream[%d]: he(%d), plain(%d)", i, val[0], keystream[0][i])
		fmt.Println(resString)
	}
}
