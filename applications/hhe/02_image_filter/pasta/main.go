// This is a sample application for adding black and white filter to an image using
// hybrid homomorphic encryption scheme: PASTA

package main

import (
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Pasta BW Image Filter Application")

	// select the symmetric parameter set
	symParams := pasta.Pasta3Param1614
	blockSize := symParams.GetBlockSize()

	// generate symmetric key
	symKey := pasta.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symPasta := pasta.NewPasta(symKey, symParams)
	symEnc := symPasta.NewEncryptor()

	// open the sample image
	var imageName = "dog_01.jpg"
	scaledImgName := utils.ReSizeImage(imageName, 5)
	numBlock, imgBounds, img, _ := utils.PreProcessImage(scaledImgName, blockSize)

	redMat := img.R
	grnMat := img.G
	bluMat := img.B

	//logger.PrintMessages(numBlock, imgBounds, redMat, grnMat, bluMat)

	// encrypt image data using symmetric cipher
	redCipherMat := make([]sym.Ciphertext, numBlock)
	grnCipherMat := make([]sym.Ciphertext, numBlock)
	bluCipherMat := make([]sym.Ciphertext, numBlock)

	for i := 0; i < numBlock; i++ {
		redCipherMat[i] = symEnc.Encrypt(redMat[i])
		grnCipherMat[i] = symEnc.Encrypt(grnMat[i])
		bluCipherMat[i] = symEnc.Encrypt(bluMat[i])
	}
	logger.PrintMemUsage("PastaEncryption")

	// decrypt image data using symmetric cipher
	redPlainMat := make([]sym.Plaintext, numBlock)
	grnPlainMat := make([]sym.Plaintext, numBlock)
	bluPlainMat := make([]sym.Plaintext, numBlock)

	for i := 0; i < numBlock; i++ {
		redPlainMat[i] = symEnc.Decrypt(redCipherMat[i])
		grnPlainMat[i] = symEnc.Decrypt(grnCipherMat[i])
		bluPlainMat[i] = symEnc.Decrypt(bluCipherMat[i])
	}
	logger.PrintMemUsage("PastaDecryption")

	decryptedImage := utils.ImageInt64{
		R: utils.ConvertPtVecToUint64Mat(redPlainMat),
		G: utils.ConvertPtVecToUint64Mat(grnPlainMat),
		B: utils.ConvertPtVecToUint64Mat(bluPlainMat),
	}

	utils.PostProcessImage("dog1.jpg", numBlock, imgBounds, blockSize, "pasta", decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.ConvertToInterfaceMat(redMat), numBlock, blockSize)
	logger.PrintSummarizedMatrix("Decrypted", utils.ConvertPtVecToInterfaceMat(redPlainMat), numBlock, blockSize)

	if reflect.DeepEqual(redMat, redPlainMat) {
		logger.PrintMessage("The plaintext after decryption is equal to the original data!")
	} else {
		logger.PrintMessage("The plaintext after decryption is different, decryption failure!")
	}
}

func encodeDataToPlainText(img [][]uint64) {

}
