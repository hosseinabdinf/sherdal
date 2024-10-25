package pasta

import (
	"encoding/binary"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	ltgo "github.com/tuneinsight/lattigo/v6/utils"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

type MFVPastaPack interface {
	Crypt(nonce []byte, kCt *rlwe.Ciphertext, dCt []uint64) (res []*rlwe.Ciphertext)
	EncKey(key []uint64) (res *rlwe.Ciphertext)
	GetGaloisElements(dataSize int) []uint64
	UpdateEvaluator(evaluator *bgv.Evaluator)
	Flatten(ciphers []*rlwe.Ciphertext) (cipher *rlwe.Ciphertext)
	Mask(cipher *rlwe.Ciphertext, mask []uint64)
}

type mfvPastaPack struct {
	logger   utils.Logger
	numRound int

	plainSize    uint64
	slots        uint64
	halfSlots    uint64
	modulus      uint64
	modDegree    uint64
	maxPrimeSize uint64

	shake  sha3.ShakeHash
	states []*rlwe.Ciphertext
	mat1   [][]uint64
	mat2   [][]uint64

	state *rlwe.Ciphertext

	logN      int
	useBatch  bool
	useBsGs   bool
	bsGsN1    uint64
	bsGsN2    uint64
	gkIndices []int

	bgvParams bgv.Parameters
	encoder   *bgv.Encoder
	evaluator *bgv.Evaluator
	encryptor *rlwe.Encryptor

	rcPt *rlwe.Plaintext
	rc   []uint64

	rem  int
	mask []uint64
}

func NEWMFVPastaPack(params Parameter, fvParams bgv.Parameters, symParams pasta.Parameter, encoder *bgv.Encoder, encryptor *rlwe.Encryptor, evaluator *bgv.Evaluator) MFVPastaPack {
	fvPastaPack := new(mfvPastaPack)
	fvPastaPack.logger = utils.NewLogger(utils.DEBUG)

	fvPastaPack.bgvParams = fvParams
	fvPastaPack.numRound = symParams.Rounds
	fvPastaPack.plainSize = uint64(symParams.BlockSize)

	fvPastaPack.logN = fvParams.LogN()
	fvPastaPack.modDegree = params.modDegree
	fvPastaPack.slots = uint64(fvParams.MaxSlots())
	fvPastaPack.halfSlots = uint64(math.Ceil(float64(fvPastaPack.slots / 2)))
	fvPastaPack.modulus = fvParams.PlaintextModulus()

	fvPastaPack.useBatch = true
	fvPastaPack.useBsGs = params.UseBsGs
	fvPastaPack.bsGsN1 = uint64(params.bSgSN1)
	fvPastaPack.bsGsN2 = uint64(params.bSgSN2)
	fvPastaPack.gkIndices = make([]int, 0)

	fvPastaPack.encoder = encoder
	fvPastaPack.encryptor = encryptor
	fvPastaPack.evaluator = evaluator

	mps := uint64(0) // max prime size
	prime := fvPastaPack.modDegree

	// count the number of valid bits of prime number, using shift to right operation
	for prime > 0 {
		mps++
		prime >>= 1
	}

	// set mps to the maximum value that can be represented with mps bits
	mps = (1 << mps) - 1

	fvPastaPack.maxPrimeSize = mps

	return fvPastaPack
}

// Crypt tranciphers SYM.Enc(dCt) into HE.Enc(res)
// Parameters:
//
//	nonce
//	kCt: homomorphically encrypted symmetric key
//	dCt: symmetrically encrypted ciphertext
//
// Returns:
//
//	res: homomorphically encrypted cipher
func (pas *mfvPastaPack) Crypt(nonce []byte, kCt *rlwe.Ciphertext, dCt []uint64) (res []*rlwe.Ciphertext) {
	size := len(dCt)
	numBlock := uint64(math.Ceil(float64(size / int(pas.plainSize))))

	res = make([]*rlwe.Ciphertext, numBlock)

	// state = homomorphically encrypted key
	pas.state = kCt.CopyNew()

	counter := make([]byte, 8)
	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		pas.initShake(nonce, counter)
		R := pas.numRound
		for r := 1; r <= R; r++ {
			pas.logger.PrintMessages("Round: ", r)
			// initialize random matrices and random constant
			pas.mat1 = pas.genRandomMatrix()
			pas.mat2 = pas.genRandomMatrix()
			pas.rc = pas.genRcVector(pas.halfSlots)

			// PASTA key stream generation circuit
			pas.matMul()
			pas.addRC()
			pas.mix()

			if r == R {
				pas.sBoxCube()
			} else {
				pas.sBoxFeistel()
			}
			//	print noise for state in each round
		}
		//	final addition
		pas.mat1 = pas.genRandomMatrix()
		pas.mat2 = pas.genRandomMatrix()
		pas.rc = pas.genRcVector(pas.halfSlots)

		pas.matMul()
		pas.addRC()
		pas.mix()

		// Q: do we need to remove the second vector?
		// A: there's no need for that

		// converting
		var sIndex = b * pas.plainSize
		var eIndex = int(math.Min(float64((b+1)*pas.plainSize), float64(size)))
		cTmp := dCt[sIndex:eIndex]
		plaintext := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
		_ = pas.encoder.Encode(cTmp, plaintext)
		// negate state --> state = state * -1
		pas.state, _ = pas.evaluator.MulNew(pas.state, -1)
		// res = symCt + (-state)
		res[b], _ = pas.evaluator.AddNew(pas.state, plaintext)
	}
	return
}

func (pas *mfvPastaPack) EncKey(key []uint64) (res *rlwe.Ciphertext) {
	dupKey := make([]uint64, pas.halfSlots+pas.plainSize)

	for i := uint64(0); i < pas.plainSize; i++ {
		dupKey[i] = key[i]
		dupKey[i+pas.halfSlots] = key[i+pas.plainSize]
	}

	pKey := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
	err := pas.encoder.Encode(dupKey, pKey)
	utils.HandleError(err)

	res, err = pas.encryptor.EncryptNew(pKey)
	utils.HandleError(err)

	return
}

func (pas *mfvPastaPack) GetGaloisElements(dataSize int) []uint64 {
	pas.prepareGkIndices(dataSize)
	galEls := make([]uint64, len(pas.gkIndices))
	for i, k := range pas.gkIndices {
		if k == 0 {
			galEls[i] = pas.bgvParams.GaloisElementForRowRotation()
		} else {
			galEls[i] = pas.bgvParams.GaloisElementForColRotation(k)
		}
	}
	return galEls
}

func (pas *mfvPastaPack) UpdateEvaluator(evaluator *bgv.Evaluator) {
	pas.evaluator = evaluator
}

func (pas *mfvPastaPack) Flatten(ciphers []*rlwe.Ciphertext) (cipher *rlwe.Ciphertext) {
	var err error
	cipher = ciphers[0].CopyNew()
	tmp := ciphers[0].CopyNew()

	for i := 1; i < len(ciphers); i++ {
		k := -(i * int(pas.plainSize))
		tmp, err = pas.evaluator.RotateColumnsNew(ciphers[i], k)
		utils.HandleError(err)
		err = pas.evaluator.Add(cipher, tmp, cipher)
		utils.HandleError(err)
	}

	return
}

func (pas *mfvPastaPack) Mask(cipher *rlwe.Ciphertext, mask []uint64) {
	var err error
	plaintext := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())

	err = pas.encoder.Encode(mask, plaintext)
	utils.HandleError(err)

	err = pas.evaluator.Mul(cipher, plaintext, cipher) // ct = ct * pt
	utils.HandleError(err)
}

// ///////////////////////		PASTA's homomorphic functions		///////////////////////

// addRC add round constant to the state
func (pas *mfvPastaPack) addRC() {
	pas.rcPt = bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
	err := pas.encoder.Encode(pas.rc, pas.rcPt)
	utils.HandleError(err)
	err = pas.evaluator.Add(pas.state, pas.rcPt, pas.state)
	utils.HandleError(err)
	return
}

func (pas *mfvPastaPack) sBoxCube() {
	tmp := pas.state.CopyNew()
	err := pas.evaluator.MulRelin(pas.state, pas.state, pas.state)
	utils.HandleError(err)
	err = pas.evaluator.MulRelin(pas.state, tmp, pas.state)
	utils.HandleError(err)
}

func (pas *mfvPastaPack) sBoxFeistel() {
	// rotate -1 to the left
	stateRotate, err := pas.evaluator.RotateColumnsNew(pas.state, -1)
	utils.HandleError(err)

	// generate masks
	masks := make([]uint64, pas.plainSize+pas.halfSlots)
	for i := range masks {
		masks[i] = 1
	}
	masks[0] = 0
	masks[pas.halfSlots] = 0
	for i := pas.plainSize; i < pas.halfSlots; i++ {
		masks[i] = 0
	}
	maskPlaintext := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
	err = pas.encoder.Encode(masks, maskPlaintext)
	utils.HandleError(err)
	// stateRot = stateRot * mask
	err = pas.evaluator.Mul(stateRotate, maskPlaintext, stateRotate)
	utils.HandleError(err)
	// stateRot = stateRot ^ 2
	err = pas.evaluator.MulRelin(stateRotate, stateRotate, stateRotate)
	utils.HandleError(err)
	// state = state + stateRot^2
	err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
	utils.HandleError(err)
}

func (pas *mfvPastaPack) matMul() {
	if pas.useBsGs {
		pas.babyStepGiantStep()
	} else {
		pas.diagonal()
	}
	return
}

func (pas *mfvPastaPack) babyStepGiantStep() {
	var err error
	matrixDim := pas.plainSize
	slots := pas.slots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if pas.bsGsN1*pas.bsGsN2 != matrixDim {
		println("WARNING: the baby-step giant-step parameters are wrong!")
	}

	// Prepare diagonal
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make([]uint64, matrixDim+pas.halfSlots)
		tmp := make([]uint64, matrixDim)

		k := i / pas.bsGsN1
		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = pas.mat1[j][(j+matrixDim-i)%matrixDim]
			tmp[j] = pas.mat2[j][(j+matrixDim-i)%matrixDim]
		}

		//	rotate
		if k != 0 {
			ltgo.RotateSlice(diag, int(k*pas.bsGsN1))
			ltgo.RotateSlice(tmp, int(k*pas.bsGsN1))
			//HHESoK.RotateSlice(diag, k*pas.bsGsN1)
			//HHESoK.RotateSlice(tmp, k*pas.bsGsN1)
		}

		//	non-full pack rotation
		if pas.halfSlots != pas.plainSize {
			diag = utils.ResizeSlice(diag, pas.halfSlots)
			tmp = utils.ResizeSlice(tmp, pas.halfSlots)

			// Perform the element swapping loop
			for m := uint64(0); m < k*pas.bsGsN1; m++ {
				indexSrc := pas.plainSize - 1 - m
				indexDest := pas.halfSlots - 1 - m
				diag[indexDest] = diag[indexSrc]
				diag[indexSrc] = 0
				tmp[indexDest] = tmp[indexSrc]
				tmp[indexSrc] = 0
			}
		}

		// Combine both diags
		diag = utils.ResizeSlice(diag, pas.slots)
		for j := pas.halfSlots; j < slots; j++ {
			diag[j] = tmp[j-pas.halfSlots]
		}

		row := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
		err = pas.encoder.Encode(diag, row)
		utils.HandleError(err)
		matrix[i] = row
	}

	//	non-full-packed rotation
	if pas.halfSlots != pas.plainSize {
		stateRotate := pas.state.CopyNew()
		err = pas.evaluator.RotateColumns(pas.state, int(pas.plainSize), stateRotate)
		utils.HandleError(err)
		err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
		utils.HandleError(err)
	}

	rotates := make([]*rlwe.Ciphertext, pas.bsGsN1)
	rotates[0] = pas.state

	var outerSum *rlwe.Ciphertext
	for j := uint64(1); j < pas.bsGsN1; j++ {
		rotates[j], err = pas.evaluator.RotateColumnsNew(rotates[j-1], -1)
		utils.HandleError(err)
	}

	for k := uint64(0); k < pas.bsGsN2; k++ {
		innerSum, _ := pas.evaluator.MulNew(rotates[0], matrix[k*pas.bsGsN1])
		for j := uint64(1); j < pas.bsGsN1; j++ {
			temp, _ := pas.evaluator.MulNew(rotates[0], matrix[k*pas.bsGsN1+j])
			_ = pas.evaluator.Add(innerSum, temp, innerSum)
		}
		if k == 0 {
			outerSum = innerSum
		} else {
			innerSum, _ = pas.evaluator.RotateColumnsNew(innerSum, -int(k*pas.bsGsN1))
			_ = pas.evaluator.Add(outerSum, innerSum, outerSum)
		}
	}
	pas.state = outerSum
}

func (pas *mfvPastaPack) diagonal() {
	var err error
	matrixDim := pas.plainSize
	slots := pas.slots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if pas.halfSlots != matrixDim {
		stateRotate, _ := pas.evaluator.RotateColumnsNew(pas.state, int(matrixDim))
		err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
		utils.HandleError(err)
	}

	//	prepare diagonal method
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make([]uint64, matrixDim+pas.halfSlots)
		for j := range diag {
			diag[j] = 0
		}

		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = pas.mat1[j][(j+matrixDim-i)%matrixDim]
			diag[j+pas.halfSlots] = pas.mat2[j][(j+matrixDim-i)%matrixDim]
		}

		row := bgv.NewPlaintext(pas.bgvParams, pas.bgvParams.MaxLevel())
		err = pas.encoder.Encode(diag, row)
		utils.HandleError(err)
		matrix[i] = row
	}

	sum := pas.state.CopyNew()
	err = pas.evaluator.Mul(sum, matrix[0], sum)
	utils.HandleError(err)
	for i := uint64(1); i < matrixDim; i++ {
		pas.state, _ = pas.evaluator.RotateColumnsNew(pas.state, -1)
		tmp, _ := pas.evaluator.MulNew(pas.state, matrix[i])
		_ = pas.evaluator.Add(sum, tmp, sum)
	}
	pas.state = sum
}

func (pas *mfvPastaPack) mix() {
	originalState := pas.state.CopyNew()
	tmp, err := pas.evaluator.RotateRowsNew(pas.state)
	utils.HandleError(err)
	err = pas.evaluator.Add(tmp, originalState, tmp)
	utils.HandleError(err)
	err = pas.evaluator.Add(originalState, tmp, pas.state)
	utils.HandleError(err)
}

// ///////////////////////		PASTA's non-homomorphic functions	///////////////////////

func (pas *mfvPastaPack) initShake(nonce []byte, counter []byte) {
	shake := sha3.NewShake128()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	if _, err := shake.Write(counter); err != nil {
		panic("Failed to init SHAKE128!")
	}
	pas.shake = shake
}

func (pas *mfvPastaPack) genRandomMatrix() [][]uint64 {
	ps := pas.plainSize
	mat := make([][]uint64, ps) // mat[ps][ps]
	for i := range mat {
		mat[i] = make([]uint64, ps) // mat[i] = [ps]
	}
	mat[0] = pas.genRandomVector(false)
	for j := uint64(1); j < ps; j++ {
		mat[j] = pas.calculateRow(mat[j-1], mat[0])
	}
	return mat
}

func (pas *mfvPastaPack) genRcVector(size uint64) []uint64 {
	ps := pas.plainSize
	rc := make([]uint64, size+ps)
	for i := uint64(0); i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	for i := size; i < (size + ps); i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	return rc
}

func (pas *mfvPastaPack) genRandomVector(allowZero bool) []uint64 {
	ps := pas.plainSize
	rc := make([]uint64, ps)
	for i := uint64(0); i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(allowZero)
	}
	return rc
}

func (pas *mfvPastaPack) generateRandomFieldElement(allowZero bool) uint64 {
	var randomByte [8]byte
	for {
		if _, err := pas.shake.Read(randomByte[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		fieldElement := binary.BigEndian.Uint64(randomByte[:]) & pas.maxPrimeSize

		if !allowZero && fieldElement == 0 {
			continue
		}

		if fieldElement < pas.modulus {
			return fieldElement
		}
	}
}

func (pas *mfvPastaPack) calculateRow(previousRow, firstRow []uint64) []uint64 {
	ps := pas.plainSize
	modulus := new(big.Int).SetUint64(pas.modulus)
	output := make([]uint64, ps)
	// =======================================
	pRow := new(big.Int).SetUint64(previousRow[ps-1])

	for j := uint64(0); j < ps; j++ {
		fRow := new(big.Int).SetUint64(firstRow[j])
		temp := new(big.Int).Mul(fRow, pRow)
		temp.Mod(temp, modulus)
		// update the index row and add the value to the temp
		if j > 0 {
			indexRow := new(big.Int).SetUint64(previousRow[j-1])
			temp.Add(temp, indexRow)
			temp.Mod(temp, modulus)
		}

		output[j] = temp.Uint64()
	}
	return output
}

// ///////////////////////	Galois and Flatten Keys ///////////////////////

// prepareGkIndices generates gkIndices required for galois elements generation
func (pas *mfvPastaPack) prepareGkIndices(dataSize int) {
	ps := int(pas.plainSize)
	rem := dataSize % ps
	numBlock := dataSize / ps
	if rem != 0 {
		numBlock++
	}

	var flattenGks []int
	for b := 1; b < numBlock; b++ {
		flattenGks = append(flattenGks, -(b * ps))
	}

	pas.addGkIndices()

	// add flatten gks
	for i := 0; i < len(flattenGks); i++ {
		pas.gkIndices = append(pas.gkIndices, flattenGks[i])
	}

	if pas.useBsGs {
		pas.addBsGsIndices()
	} else {
		pas.addDiagonalIndices(dataSize)
	}
}

func (pas *mfvPastaPack) addGkIndices() {
	pas.gkIndices = append(pas.gkIndices, 0)
	pas.gkIndices = append(pas.gkIndices, -1)
	if pas.plainSize*2 != pas.slots {
		pas.gkIndices = append(pas.gkIndices, int(pas.plainSize))
	}
	if pas.useBsGs {
		for k := uint64(1); k < pas.bsGsN2; k++ {
			pas.gkIndices = append(pas.gkIndices, -int(k*pas.bsGsN1))
		}
	}
}

func (pas *mfvPastaPack) addBsGsIndices() {
	mul := pas.bsGsN1 * pas.bsGsN2
	pas.addDiagonalIndices(int(mul))
	if pas.bsGsN1 == 1 || pas.bsGsN2 == 1 {
		return
	}
	for k := uint64(1); k < pas.bsGsN2; k++ {
		pas.gkIndices = append(pas.gkIndices, int(k*pas.bsGsN1))
	}
}

func (pas *mfvPastaPack) addDiagonalIndices(size int) {
	if uint64(size)*2 != pas.slots {
		pas.gkIndices = append(pas.gkIndices, -size)
	}
	pas.gkIndices = append(pas.gkIndices, 1)
}
