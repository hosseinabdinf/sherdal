package hera

import (
	"image"
	"reflect"
	"sherdal/hhe/sym/hera"
	"sherdal/utils"
)

func Run(params hera.Parameter, imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	// generate symmetric key
	symKey := hera.GenerateSymKey(params)

	// initialize the symmetric cipher
	symRubato := hera.NewHera(symKey, params)
	symEnc := symRubato.NewEncryptor()

	// This will be equal to number of blocks and maxSlot in the HE case
	rows := 1
	cols := len(img.R)

	// encrypt image data using symmetric cipher
	redCipher := symEnc.Encrypt(img.R)
	grnCipher := symEnc.Encrypt(img.G)
	bluCipher := symEnc.Encrypt(img.B)
	logger.PrintMemUsage("HeraEncryption")

	// decrypt image data using symmetric cipher
	decryptedVec := utils.ImageUint64Vec{
		R: symEnc.Decrypt(redCipher),
		G: symEnc.Decrypt(grnCipher),
		B: symEnc.Decrypt(bluCipher),
	}
	logger.PrintMemUsage("HeraDecryption")

	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)

	utils.PostProcessUintImage("hera", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	if reflect.DeepEqual(img.R, decryptedVec.R) {
		logger.PrintMessage("Pass: Plaintext data and decrypted are equal!")
	} else {
		logger.PrintMessage("Fail: Plaintext data and decrypted are not equal!")
	}
}
