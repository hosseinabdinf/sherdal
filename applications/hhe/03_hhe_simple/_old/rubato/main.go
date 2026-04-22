package main

import (
	"fmt"

	"github.com/hosseinabdinf/sherdal/internal/old_fv"

	rubato2 "github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/hosseinabdinf/sherdal/hhe/_old/rubato"
)

func main() {
	var kgen old_fv.KeyGenerator
	var fvEncoder old_fv.MFVEncoder
	var sk *old_fv.SecretKey
	var pk *old_fv.PublicKey
	var fvEncryptor old_fv.MFVEncryptor
	var fvDecryptor old_fv.MFVDecryptor
	var fvEvaluator old_fv.MFVEvaluator
	var fvNoiseEstimator old_fv.MFVNoiseEstimator
	var mfvRubato rubato.MFVRubato

	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var keystreamCt []*old_fv.Ciphertext

	blocksize := rubato.RubatoParams[rubato.RUBATO128L].Blocksize
	//numRound := rubato.RubatoParams[rubato.RUBATO128L].NumRound
	plainModulus := rubato.RubatoParams[rubato.RUBATO128L].PlainModulus
	//sigma := rubato.RubatoParams[rubato.RUBATO128L].Sigma

	hbtpParams := old_fv.RtFRubatoParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	params.SetPlainModulus(plainModulus)
	params.SetLogFVSlots(params.LogN())

	// Scheme context and keys
	fmt.Println("Key generation...")
	kgen = old_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(192)

	fvEncoder = old_fv.NewMFVEncoder(params)
	fvEncryptor = old_fv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = old_fv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = old_fv.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	fvEvaluator = old_fv.NewMFVEvaluator(params, old_fv.EvaluationKey{Rlk: rlk}, nil)

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
		resString := fmt.Sprintf("keystream[%d]: internal(%d), plain(%d)", i, val[0], keystream[0][i])
		fmt.Println(resString)
	}
}
