package rubato

import (
	"image"
	"sherdal/hhe/rubato"
	rubato2 "sherdal/ske/rubato"
	"sherdal/utils"
)

func HHEImgEncApp(imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	symParams := rubato2.Rubato2Param2516

	cfg := rubato.Config{
		Preset:          rubato.Rubato128S,
		BGVLogN:         14,
		SymmetricParams: symParams,
	}

	fv_rubato, err := rubato.NewRubato(cfg)
	if err != nil {
		panic(err)
	}

	key := rubato2.GenerateSymKey(symParams)

	if err := fv_rubato.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	symCipher := rubato2.NewRubato(key, symParams).NewEncryptor()

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	// This will be equal to number of blocks and maxSlot in the HE case
	rows := 1
	cols := len(img.R)

	// encrypt image data using symmetric cipher
	redCipher := symCipher.EncryptWithNonce(img.R, nonce)
	grnCipher := symCipher.EncryptWithNonce(img.G, nonce)
	bluCipher := symCipher.EncryptWithNonce(img.B, nonce)
	logger.PrintMemUsage("RubatoEncryption")

	heCipherRed, err := fv_rubato.TranscipherSymCiphertext(redCipher, nonce)
	if err != nil {
		panic(err)
	}
	logger.PrintMemUsage("TranscipherSymCiphertextRed")

	heCipherGrn, err := fv_rubato.TranscipherSymCiphertext(grnCipher, nonce)
	if err != nil {
		panic(err)
	}
	logger.PrintMemUsage("TranscipherSymCiphertextGrn")

	heCipherBlu, err := fv_rubato.TranscipherSymCiphertext(bluCipher, nonce)
	if err != nil {
		panic(err)
	}
	logger.PrintMemUsage("TranscipherSymCiphertextBlu")

	decryptedRed, err := fv_rubato.Decrypt(heCipherRed, len(img.R))
	if err != nil {
		panic(err)
	}

	decryptedGrn, err := fv_rubato.Decrypt(heCipherGrn, len(img.G))
	if err != nil {
		panic(err)
	}

	decryptedBlu, err := fv_rubato.Decrypt(heCipherBlu, len(img.B))
	if err != nil {
		panic(err)
	}
	logger.PrintMemUsage("RubatoDecryption")

	decryptedVec := utils.ImageUint64Vec{
		R: decryptedRed,
		G: decryptedGrn,
		B: decryptedBlu,
	}

	// re-construct and save the decrypted Image
	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)
	utils.PostProcessUintImage("rubato_hhe", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	precision, lost := symCipher.GetPrecisionAndLoss(img.R, decryptedVec.R)
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)

}
