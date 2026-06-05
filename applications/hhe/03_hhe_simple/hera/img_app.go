package he1hera

import (
	"image"
	"math"
	"sync"

	"github.com/hosseinabdinf/sherdal/hhe/hera"

	hera2 "github.com/hosseinabdinf/sherdal/ske/hera"
	"github.com/hosseinabdinf/sherdal/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func HHEImgEncApp(imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	symParams := hera2.Hera4Params2516

	cfg := hera.Config{
		Preset:          hera.Hera128AF,
		BGVLogN:         15,
		SymmetricParams: symParams,
	}

	fvHeraRed, err := hera.NewHera(cfg)
	if err != nil {
		panic(err)
	}
	fvHeraGrn, err := hera.NewHera(cfg)
	if err != nil {
		panic(err)
	}
	fvHeraBlu, err := hera.NewHera(cfg)
	if err != nil {
		panic(err)
	}

	key := hera2.GenerateSymKey(symParams)

	if err := fvHeraRed.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvHeraGrn.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvHeraBlu.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	symCipher := hera2.NewHera(key, symParams).NewEncryptor()

	nonce := []byte{10, 11, 12, 13, 14, 15, 16, 17}

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
	logger.PrintMemUsage("HeraEncryption")

	// Transcipher channels concurrently using their own Hera instances to prevent evaluator data races
	var (
		heCipherRed, heCipherGrn, heCipherBlu []*rlwe.Ciphertext
		errRed, errGrn, errBlu                error
		transWg                               sync.WaitGroup
	)
	transWg.Add(3)
	go func() {
		defer transWg.Done()
		heCipherRed, errRed = fvHeraRed.TranscipherSymCiphertext(redCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherGrn, errGrn = fvHeraGrn.TranscipherSymCiphertext(grnCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherBlu, errBlu = fvHeraBlu.TranscipherSymCiphertext(bluCipher, nonce)
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

	// Decrypt channels concurrently using their own Hera instances
	var (
		decryptedRed, decryptedGrn, decryptedBlu []uint64
		decErrRed, decErrGrn, decErrBlu          error
		decWg                                    sync.WaitGroup
	)
	decWg.Add(3)
	go func() {
		defer decWg.Done()
		decryptedRed, decErrRed = fvHeraRed.Decrypt(heCipherRed, len(img.R))
	}()
	go func() {
		defer decWg.Done()
		decryptedGrn, decErrGrn = fvHeraGrn.Decrypt(heCipherGrn, len(img.G))
	}()
	go func() {
		defer decWg.Done()
		decryptedBlu, decErrBlu = fvHeraBlu.Decrypt(heCipherBlu, len(img.B))
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
	logger.PrintMemUsage("HeraDecryption")

	decryptedVec := utils.ImageUint64Vec{
		R: decryptedRed,
		G: decryptedGrn,
		B: decryptedBlu,
	}

	// re-construct and save the decrypted Image
	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)
	utils.PostProcessUintImage("hera_hhe", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	precision, lost := getPrecisionAndLoss(img.R, decryptedVec.R)
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)
}

func getPrecisionAndLoss(plaintext, decrypted []uint64) (precision float64, lossPercentage float64) {
	if len(plaintext) != len(decrypted) {
		panic("plaintext and decrypted slices must have the same length")
	}

	var totalPrecision float64
	var totalLoss float64

	for i := range plaintext {
		if plaintext[i] == 0 {
			if decrypted[i] == 0 {
				totalPrecision += 100
				continue
			}
			totalLoss += 100
			continue
		}

		relativeLoss := math.Abs(float64(decrypted[i])-float64(plaintext[i])) / float64(plaintext[i]) * 100
		if relativeLoss > 100 {
			relativeLoss = 100
		}

		totalLoss += relativeLoss
		totalPrecision += 100 - relativeLoss
	}

	precision = totalPrecision / float64(len(plaintext))
	lossPercentage = totalLoss / float64(len(plaintext))

	return precision, lossPercentage
}
