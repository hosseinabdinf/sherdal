package pasta

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

type HEPasta struct {
	logger  utils.Logger
	fvPasta BGVPasta

	params    Parameter
	symParams pasta.Parameter
	bfvParams bgv.Parameters
	encoder   *bgv.Encoder
	evaluator *bgv.Evaluator
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	keyGenerator *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	pk           *rlwe.PublicKey
	rlk          *rlwe.RelinearizationKey
	glk          []*rlwe.GaloisKey
	evk          *rlwe.MemEvaluationKeySet

	symKeyCt *rlwe.Ciphertext

	N       int
	outSize int
}

func NewHEPasta() *HEPasta {
	hePasta := &HEPasta{
		logger:       utils.NewLogger(utils.DEBUG),
		params:       Parameter{},
		symParams:    pasta.Parameter{},
		fvPasta:      nil,
		bfvParams:    bgv.Parameters{},
		encoder:      nil,
		evaluator:    nil,
		encryptor:    nil,
		decryptor:    nil,
		keyGenerator: nil,
		sk:           nil,
		pk:           nil,
		glk:          nil,
		rlk:          nil,
		evk:          nil,
		symKeyCt:     nil,
		N:            0,
		outSize:      0,
	}
	return hePasta
}

func (pas *HEPasta) InitParams(homParams Parameter, symParams pasta.Parameter) {
	pas.params = homParams
	pas.symParams = symParams
	pas.outSize = symParams.BlockSize
	pas.N = 1 << homParams.logN
	// create bfvParams from Literal
	fvParams, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             homParams.logN,
		LogQ:             []int{47, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34},
		LogP:             []int{47, 47, 47, 47},
		PlaintextModulus: homParams.plainMod,
	})
	//fvParams, err := bgv.NewParametersFromLiteral(configs.BGVParamsN15QP880)
	utils.HandleError(err)
	pas.bfvParams = fvParams
}

func (pas *HEPasta) HEKeyGen() {
	params := pas.bfvParams

	pas.keyGenerator = rlwe.NewKeyGenerator(params)
	pas.sk, pas.pk = pas.keyGenerator.GenKeyPairNew()

	pas.encoder = bgv.NewEncoder(params)
	pas.decryptor = bgv.NewDecryptor(params, pas.sk)
	pas.encryptor = bgv.NewEncryptor(params, pas.pk)

	fmt.Printf("=== Parameters : N=%d, T=%d, LogQP = %f, sigma = %T %v, logMaxSlot= %d \n", 1<<params.LogN(), params.PlaintextModulus(), params.LogQP(), params.Xe(), params.Xe(), params.LogMaxSlots())
}

func (pas *HEPasta) InitFvPasta() BGVPasta {
	pas.fvPasta = NEWBFVPasta(pas.params, pas.bfvParams, pas.symParams, pas.encoder, pas.encryptor, pas.decryptor, pas.evaluator)
	return pas.fvPasta
}

func (pas *HEPasta) CreateGaloisKeys(dataSize int) {
	pas.rlk = pas.keyGenerator.GenRelinearizationKeyNew(pas.sk)
	galEls := pas.fvPasta.GetGaloisElements(dataSize)
	pas.glk = pas.keyGenerator.GenGaloisKeysNew(galEls, pas.sk)
	pas.evk = rlwe.NewMemEvaluationKeySet(pas.rlk, pas.glk...)
	// BGV scheme --> scale invariant = false | BFV scheme --> scale invariant = true
	pas.evaluator = bgv.NewEvaluator(pas.bfvParams, pas.evk, false)
	pas.fvPasta.UpdateEvaluator(pas.evaluator)
}

func (pas *HEPasta) EncryptSymKey(key sym.Key) {
	pas.symKeyCt = pas.fvPasta.EncKey(key)
	pas.logger.PrintMessages(">> Symmetric Key #slots: ", pas.symKeyCt.Slots())
}

func (pas *HEPasta) Transcipher(nonce []byte, dCt []uint64) []*rlwe.Ciphertext {
	tranCipData := pas.fvPasta.Crypt(nonce, pas.symKeyCt, dCt)
	return tranCipData
}

// Decrypt homomorphic ciphertext
func (pas *HEPasta) Decrypt(ciphertext *rlwe.Ciphertext) (res []uint64) {
	tmp := make([]uint64, pas.bfvParams.MaxSlots())
	pt := pas.decryptor.DecryptNew(ciphertext)
	err := pas.encoder.Decode(pt, tmp)
	utils.HandleError(err)
	return tmp[:pas.symParams.BlockSize]
}
