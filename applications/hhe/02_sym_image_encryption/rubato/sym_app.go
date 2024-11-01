package rubato

import (
	"image"
	"sherdal/hhe/sym/rubato"
	"sherdal/utils"
)

// ImgEncApp Image Encryption Application using Rubato symmetric cipher
func ImgEncApp(params rubato.Parameter, imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	// generate symmetric key
	symKey := rubato.GenerateSymKey(params)

	// initialize the symmetric cipher
	symRubato := rubato.NewRubato(symKey, params)
	symEnc := symRubato.NewEncryptor()

	// This will be equal to number of blocks and maxSlot in the HE case
	rows := 1
	cols := len(img.R)

	// encrypt image data using symmetric cipher
	redCipher := symEnc.Encrypt(img.R)
	grnCipher := symEnc.Encrypt(img.G)
	bluCipher := symEnc.Encrypt(img.B)
	logger.PrintMemUsage("RubatoEncryption")

	// decrypt image data using symmetric cipher
	decryptedVec := utils.ImageUint64Vec{
		R: symEnc.Decrypt(redCipher),
		G: symEnc.Decrypt(grnCipher),
		B: symEnc.Decrypt(bluCipher),
	}
	logger.PrintMemUsage("RubatoDecryption")

	// re-construct and save the decrypted Image
	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)
	utils.PostProcessUintImage("rubato", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	precision, lost := symEnc.GetPrecisionAndLoss(img.R, decryptedVec.R)
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)
}
