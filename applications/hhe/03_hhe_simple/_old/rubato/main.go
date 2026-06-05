package main

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/pkg/_old_fv_org"

	rubato2 "github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/hosseinabdinf/sherdal/hhe/_old/rubato"
)

func main() {
	var kgen _old_fv_org.KeyGenerator
	var fvEncoder _old_fv_org.MFVEncoder
	var sk *_old_fv_org.SecretKey
	var pk *_old_fv_org.PublicKey
	var fvEncryptor _old_fv_org.MFVEncryptor
	var fvDecryptor _old_fv_org.MFVDecryptor
	var fvEvaluator _old_fv_org.MFVEvaluator
	var fvNoiseEstimator _old_fv_org.MFVNoiseEstimator
	var mfvRubato rubato.MFVRubato

	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var keystreamCt []*_old_fv_org.Ciphertext

	blocksize := rubato.RubatoParams[rubato.RUBATO128L].Blocksize
	//numRound := rubato.RubatoParams[rubato.RUBATO128L].NumRound
	plainModulus := rubato.RubatoParams[rubato.RUBATO128L].PlainModulus
	//sigma := rubato.RubatoParams[rubato.RUBATO128L].Sigma

	hbtpParams := _old_fv_org.RtFRubatoParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	params.SetPlainModulus(plainModulus)
	params.SetLogFVSlots(params.LogN())

	// Scheme context and keys
	fmt.Println("Key generation...")
	kgen = _old_fv_org.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(192)

	fvEncoder = _old_fv_org.NewMFVEncoder(params)
	fvEncryptor = _old_fv_org.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = _old_fv_org.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = _old_fv_org.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	fvEvaluator = _old_fv_org.NewMFVEvaluator(params, _old_fv_org.EvaluationKey{Rlk: rlk}, nil)

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

	symParams := rubato2.Rubato2Param2516
	symRubato := rubato2.NewRubato(key, symParams)
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
		resString := fmt.Sprintf("keystream[%d]: pkg(%d), plain(%d)", i, val[0], keystream[0][i])
		fmt.Println(resString)
	}
}
