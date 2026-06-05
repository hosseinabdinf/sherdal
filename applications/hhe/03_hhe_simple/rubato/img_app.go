package rubato

import (
	"image"
	"sync"

	"github.com/hosseinabdinf/sherdal/hhe/rubato"

	rubato2 "github.com/hosseinabdinf/sherdal/ske/rubato"
	"github.com/hosseinabdinf/sherdal/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func HHEImgEncApp(imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	symParams := rubato2.Rubato3Param2516

	cfg := rubato.Config{
		Preset:          rubato.Rubato128S,
		BGVLogN:         14,
		SymmetricParams: symParams,
	}

	fvRubatoRed, err := rubato.NewRubato(cfg)
	if err != nil {
		panic(err)
	}
	fvRubatoGrn, err := rubato.NewRubato(cfg)
	if err != nil {
		panic(err)
	}
	fvRubatoBlu, err := rubato.NewRubato(cfg)
	if err != nil {
		panic(err)
	}

	key := rubato2.GenerateSymKey(symParams)

	if err := fvRubatoRed.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvRubatoGrn.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvRubatoBlu.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	symCipher := rubato2.NewRubato(key, symParams).NewEncryptor()

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	// This will be equal to number of blocks and maxSlot in the HE case
	rows := 1
	cols := len(img.R)

	// encrypt image data using symmetric cipher in parallel (each channel's internal blocks are also parallel)
	var (
		redCipher, grnCipher, bluCipher []uint64
		encWg                           sync.WaitGroup
	)
	encWg.Add(3)
	go func() {
		defer encWg.Done()
		redCipher = symCipher.EncryptWithNonce(img.R, nonce)
	}()
	go func() {
		defer encWg.Done()
		grnCipher = symCipher.EncryptWithNonce(img.G, nonce)
	}()
	go func() {
		defer encWg.Done()
		bluCipher = symCipher.EncryptWithNonce(img.B, nonce)
	}()
	encWg.Wait()
	logger.PrintMemUsage("RubatoEncryption")

	// Transcipher channels concurrently using their own Rubato instances to prevent evaluator data races
	var (
		heCipherRed, heCipherGrn, heCipherBlu []*rlwe.Ciphertext
		errRed, errGrn, errBlu                error
		transWg                               sync.WaitGroup
	)
	transWg.Add(3)
	go func() {
		defer transWg.Done()
		heCipherRed, errRed = fvRubatoRed.TranscipherSymCiphertext(redCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherGrn, errGrn = fvRubatoGrn.TranscipherSymCiphertext(grnCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherBlu, errBlu = fvRubatoBlu.TranscipherSymCiphertext(bluCipher, nonce)
	}()
	transWg.Wait()

	if errRed != nil {
		panic(errRed)
	}
	if errGrn != nil {
		panic(errGrn)
	}
	if errBlu != nil {
		panic(errBlu)
	}
	logger.PrintMemUsage("TranscipherSymCiphertextAllChannels")

	// Decrypt channels concurrently using their own Rubato instances
	var (
		decryptedRed, decryptedGrn, decryptedBlu []uint64
		decErrRed, decErrGrn, decErrBlu          error
		decWg                                    sync.WaitGroup
	)
	decWg.Add(3)
	go func() {
		defer decWg.Done()
		decryptedRed, decErrRed = fvRubatoRed.Decrypt(heCipherRed, len(img.R))
	}()
	go func() {
		defer decWg.Done()
		decryptedGrn, decErrGrn = fvRubatoGrn.Decrypt(heCipherGrn, len(img.G))
	}()
	go func() {
		defer decWg.Done()
		decryptedBlu, decErrBlu = fvRubatoBlu.Decrypt(heCipherBlu, len(img.B))
	}()
	decWg.Wait()

	if decErrRed != nil {
		panic(decErrRed)
	}
	if decErrGrn != nil {
		panic(decErrGrn)
	}
	if decErrBlu != nil {
		panic(decErrBlu)
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
