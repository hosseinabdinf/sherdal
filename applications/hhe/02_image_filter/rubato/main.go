package main

import (
	"sherdal/hhe/sym"
	"sherdal/hhe/sym/rubato"
	"sherdal/utils"
)

func main() {
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintHeader("Pasta BW Image Filter Application")

	// select the symmetric parameter set
	symParams := rubato.Rubato5Param2616
	blockSize := 1

	// generate symmetric key
	symKey := rubato.GenerateSymKey(symParams)

	// initialize the symmetric cipher
	symRubato := rubato.NewRubato(symKey, symParams)
	symEnc := symRubato.NewEncryptor()

	// open the sample image
	var imageName = "dog_01.jpg"
	scaledImgName := utils.ReSizeImage(imageName, 5)
	numBlock, imgBounds, img, _ := utils.PreProcessImage(scaledImgName, blockSize)

	redMat := img.R
	grnMat := img.G
	bluMat := img.B

	//logger.PrintMessages(numBlock, imgBounds, redMat, grnMat, bluMat)
	cSize := len(redMat[0])
	// encrypt image data using symmetric cipher
	redCipher := make(sym.Ciphertext, cSize)
	grnCipher := make(sym.Ciphertext, cSize)
	bluCipher := make(sym.Ciphertext, cSize)

	redCipher = symEnc.Encrypt(redMat[0])
	grnCipher = symEnc.Encrypt(grnMat[0])
	bluCipher = symEnc.Encrypt(bluMat[0])

	logger.PrintMemUsage("PastaEncryption")

	// decrypt image data using symmetric cipher
	redPlain := make(sym.Plaintext, cSize)
	grnPlain := make(sym.Plaintext, cSize)
	bluPlain := make(sym.Plaintext, cSize)

	redPlain = symEnc.Decrypt(redCipher)
	grnPlain = symEnc.Decrypt(grnCipher)
	bluPlain = symEnc.Decrypt(bluCipher)

	logger.PrintMemUsage("PastaDecryption")

	decryptedImage := utils.ImageInt64{
		R: utils.ConvertPtToUint64Mat(redPlain),
		G: utils.ConvertPtToUint64Mat(grnPlain),
		B: utils.ConvertPtToUint64Mat(bluPlain),
	}

	utils.PostProcessImage("dog1.jpg", numBlock, imgBounds, blockSize, "rubato", decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.ConvertToInterfaceMat(redMat), numBlock, blockSize)
	//logger.PrintSummarizedMatrix("Decrypted", utils.ConvertPtVecToInterfaceMat(utils.ConvertPtToUint64Mat(redPlain)), numBlock, blockSize)

	precision, lost := symEnc.GetPrecisionAndLoss(redMat[0], utils.ConvertPtToUint64Mat(redPlain)[0])
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)
}
