package main

import (
	"reflect"
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/rubato"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Rubato BW Image Filter Application")

	// select the symmetric parameter set
	symParams := rubato.Rubato5Param2616
	maxSlot := symParams.GetBlockSize()
	// generate symmetric key
	symKey := rubato.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symPasta := rubato.NewPasta(symKey, symParams)
	symEnc := symPasta.NewEncryptor()

	// open the sample image
	var imageName = "dog_01.jpg"
	scaledImgName := utils.ReSizeImage(imageName, 10)
	numBlock, imgBounds, img, _ := utils.PreProcessImage(scaledImgName, maxSlot)

	utils.PostProcessImage("dog.jpg", numBlock, imgBounds, maxSlot, "rubato", img)

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
		R: utils.ConvertPtxToUi64Slice(redPlainMat),
		G: utils.ConvertPtxToUi64Slice(grnPlainMat),
		B: utils.ConvertPtxToUi64Slice(bluPlainMat),
	}

	utils.PostProcessImage("dog1.jpg", numBlock, imgBounds, maxSlot, "rubato", decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.ConvertToInterfaceSlice(redMat), numBlock, maxSlot)
	logger.PrintSummarizedMatrix("Decrypted", utils.ConvertPToInterfaceSlice(redPlainMat), numBlock, maxSlot)

	if reflect.DeepEqual(redMat, redPlainMat) {
		logger.PrintMessage("The plaintext after decryption is equal to the original data!")
	} else {
		logger.PrintMessage("The plaintext after decryption is different, decryption failure!")
	}
}
