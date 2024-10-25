package applications

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"sherdal/utils"
	"strconv"
)

type BwCKKS struct{}

func (bw BwCKKS) Client(pubParams []byte, data []float64) (pk []byte, evk []byte, ciphers [][]byte) {

	return pk, evk, ciphers
}

func (bw BwCKKS) Server() {

}

// BWFilterCKKS add a bw filter to input image using ckks
func BWFilterCKKS(imgName string, paramsLiteral ckks.ParametersLiteral, testFlag bool) {
	logger := utils.NewLogger(utils.DEBUG)
	var err error
	// ================================================================
	// user side
	// initialize the ckks scheme requirements with default parameters
	params, ecd, enc, dec, evl := utils.InitCKKS(paramsLiteral)
	_, img := utils.GetRGBImage(imgName)
	numBlock, imgMat := img.PreProcessImage(params.MaxSlots())

	redMat := imgMat.R
	grnMat := imgMat.G
	bluMat := imgMat.B

	// Encode each color vector into a RLWE plaintext
	redPTs := make([]*rlwe.Plaintext, numBlock)
	grnPTs := make([]*rlwe.Plaintext, numBlock)
	bluPTs := make([]*rlwe.Plaintext, numBlock)
	for i := 0; i < numBlock; i++ {
		redPT := ckks.NewPlaintext(params, params.MaxLevel())
		grnPT := ckks.NewPlaintext(params, params.MaxLevel())
		bluPT := ckks.NewPlaintext(params, params.MaxLevel())

		err = ecd.Encode(redMat[i], redPT)
		utils.HandleError(err)
		redPTs[i] = redPT

		err = ecd.Encode(grnMat[i], grnPT)
		utils.HandleError(err)
		grnPTs[i] = grnPT

		err = ecd.Encode(bluMat[i], bluPT)
		utils.HandleError(err)
		bluPTs[i] = bluPT
	}

	// encrypt the RLWE plaintexts
	redCTs := make([]*rlwe.Ciphertext, numBlock)
	grnCTs := make([]*rlwe.Ciphertext, numBlock)
	bluCTs := make([]*rlwe.Ciphertext, numBlock)
	for i := 0; i < numBlock; i++ {
		redCTs[i], err = enc.EncryptNew(redPTs[i])
		utils.HandleError(err)

		grnCTs[i], err = enc.EncryptNew(grnPTs[i])
		utils.HandleError(err)

		bluCTs[i], err = enc.EncryptNew(bluPTs[i])
		utils.HandleError(err)
	}

	logN := strconv.Itoa(params.LogN())

	err = utils.Serialize(redCTs[0], "./outputs/CKKS_ciphertext_"+logN+".bin")
	if err != nil {
		fmt.Println(err)
	}
	// ================================================================
	// Server side
	// normalize each color homomorphically using [ct * pt (1/norm)]
	normConst := (1.0 / 65535.0) * 255.0
	nRCTs := make([]*rlwe.Ciphertext, numBlock)
	nGCTs := make([]*rlwe.Ciphertext, numBlock)
	nBCTs := make([]*rlwe.Ciphertext, numBlock)
	for i := 0; i < numBlock; i++ {
		nRCTs[i], err = evl.MulNew(redCTs[i], normConst)
		utils.HandleError(err)
		nGCTs[i], err = evl.MulNew(grnCTs[i], normConst)
		utils.HandleError(err)
		nBCTs[i], err = evl.MulNew(bluCTs[i], normConst)

		noise, _, _ := rlwe.Norm(nRCTs[i], dec)
		logger.PrintFormatted("STD(noise): %f\n", noise)
	}

	// if testFlag is true it shows the precision for results
	if testFlag {
		want := make([][]float64, numBlock)
		for i := 0; i < numBlock; i++ {
			want[i] = make([]float64, params.MaxSlots())
			for j := 0; j < len(redMat[i]); j++ {
				want[i][j] = normConst * redMat[i][j]
			}
		}
		logger.PrintSummarizedMatrix("Want", utils.MatrixToInterfaceMat(want), numBlock, params.MaxSlots())

		have := make([][]float64, numBlock)
		for i := 0; i < numBlock; i++ {
			ctt := nRCTs[i]
			have[i] = make([]float64, ctt.Slots())
			err = ecd.Decode(dec.DecryptNew(ctt), have[i])
			utils.HandleError(err)
		}
		logger.PrintSummarizedMatrix("Have", utils.MatrixToInterfaceMat(have), numBlock, params.MaxSlots())

		fmt.Println(ckks.GetPrecisionStats(params, ecd, nil, have[0], want[0], 0, false).String())
	}

	// calculate the greyscale value using [(nR + nG + nB)  ct * pt (1/3)]
	avgConst := 1.0 / 3.0
	grayCTs := make([]*rlwe.Ciphertext, numBlock)
	for i := 0; i < numBlock; i++ {
		rgCT, err := evl.AddNew(nRCTs[i], nGCTs[i])
		utils.HandleError(err)
		rgbCT, err := evl.AddNew(nBCTs[i], rgCT)
		utils.HandleError(err)
		grayCTs[i], err = evl.MulNew(rgbCT, avgConst)
		utils.HandleError(err)
	}

	// ================================================================
	// user side
	// Decrypt the grayscale ciphertext and save the edited image
	grayPTs := make([]*rlwe.Plaintext, numBlock)
	grayVCs := make([][]float64, numBlock)
	for i := 0; i < numBlock; i++ {
		grayPT := ckks.NewPlaintext(params, params.MaxLevel())
		dec.Decrypt(grayCTs[i], grayPT)
		grayPTs[i] = grayPT
		grayVCs[i] = make([]float64, params.MaxSlots())
		err = ecd.Decode(grayPTs[i], grayVCs[i])
		utils.HandleError(err)
	}

	utils.PostProcessBWImage("ckksDog.jpg", numBlock, img.Bounds, params.MaxSlots(), strconv.Itoa(params.LogN()), grayVCs)
}
