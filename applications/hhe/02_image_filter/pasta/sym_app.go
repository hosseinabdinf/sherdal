// This is a sample application for adding black and white filter to an image using
// hybrid homomorphic encryption scheme: PASTA

package pasta

import (
	"image"
	"reflect"
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
)

func Run(params pasta.Parameter, imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	// generate symmetric key
	symKey := pasta.GenerateSymKey(params)

	// initialize the symmetric cipher
	symPasta := pasta.NewPasta(symKey, params)
	symEnc := symPasta.NewEncryptor()

	// This will be equal to number of blocks and maxSlot in the HE case
	rows := 1
	cols := len(img.R)

	// encrypt image data using symmetric cipher
	redCipher := symEnc.Encrypt(img.R)
	grnCipher := symEnc.Encrypt(img.G)
	bluCipher := symEnc.Encrypt(img.B)
	logger.PrintMemUsage("PastaEncryption")

	// decrypt image data using symmetric cipher
	decryptedVec := utils.ImageUint64Vec{
		R: symEnc.Decrypt(redCipher),
		G: symEnc.Decrypt(grnCipher),
		B: symEnc.Decrypt(bluCipher),
	}
	logger.PrintMemUsage("PastaDecryption")

	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)

	utils.PostProcessUintImage("pasta", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	if reflect.DeepEqual(img.R, decryptedVec.R) {
		logger.PrintMessage("Pass: Plaintext data and decrypted are equal!")
	} else {
		logger.PrintMessage("Fail: Plaintext data and decrypted are not equal!")
	}

}
