package pasta2

import (
	"image"
	"math"
	"sync"

	"github.com/hosseinabdinf/sherdal/hhe/pasta2"

	sympasta2 "github.com/hosseinabdinf/sherdal/ske/pasta2"
	"github.com/hosseinabdinf/sherdal/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func HHEImgEncApp(imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	symParams := sympasta2.Pasta4Param3215

	cfg := pasta2.Config{
		Preset:          pasta2.Pasta2_3_3215,
		BGVLogN:         15,
		SymmetricParams: symParams,
	}

	fvPastaRed, err := pasta2.NewPasta2(cfg)
	if err != nil {
		panic(err)
	}
	fvPastaGrn, err := pasta2.NewPasta2(cfg)
	if err != nil {
		panic(err)
	}
	fvPastaBlu, err := pasta2.NewPasta2(cfg)
	if err != nil {
		panic(err)
	}

	key := sympasta2.GenerateSymKey(symParams)

	if err := fvPastaRed.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvPastaGrn.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvPastaBlu.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

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
		encryptor := sympasta2.NewPasta2(key, symParams).NewEncryptor()
		redCipher = encryptor.EncryptWithNonce(img.R, nonce)
	}()
	go func() {
		defer encWg.Done()
		encryptor := sympasta2.NewPasta2(key, symParams).NewEncryptor()
		grnCipher = encryptor.EncryptWithNonce(img.G, nonce)
	}()
	go func() {
		defer encWg.Done()
		encryptor := sympasta2.NewPasta2(key, symParams).NewEncryptor()
		bluCipher = encryptor.EncryptWithNonce(img.B, nonce)
	}()
	encWg.Wait()
	logger.PrintMemUsage("Pasta2Encryption")

	// Transcipher channels concurrently using their own Pasta2 instances to prevent evaluator data races
	var (
		heCipherRed, heCipherGrn, heCipherBlu []*rlwe.Ciphertext
		errRed, errGrn, errBlu                error
		transWg                               sync.WaitGroup
	)
	transWg.Add(3)
	go func() {
		defer transWg.Done()
		heCipherRed, errRed = fvPastaRed.TranscipherSymCiphertext(redCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherGrn, errGrn = fvPastaGrn.TranscipherSymCiphertext(grnCipher, nonce)
	}()
	go func() {
		defer transWg.Done()
		heCipherBlu, errBlu = fvPastaBlu.TranscipherSymCiphertext(bluCipher, nonce)
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

	// Decrypt channels concurrently using their own Pasta2 instances
	var (
		decryptedRed, decryptedGrn, decryptedBlu []uint64
		decErrRed, decErrGrn, decErrBlu          error
		decWg                                    sync.WaitGroup
	)
	decWg.Add(3)
	go func() {
		defer decWg.Done()
		decryptedRed, decErrRed = fvPastaRed.Decrypt(heCipherRed, len(img.R))
	}()
	go func() {
		defer decWg.Done()
		decryptedGrn, decErrGrn = fvPastaGrn.Decrypt(heCipherGrn, len(img.G))
	}()
	go func() {
		defer decWg.Done()
		decryptedBlu, decErrBlu = fvPastaBlu.Decrypt(heCipherBlu, len(img.B))
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
	logger.PrintMemUsage("Pasta2Decryption")

	decryptedVec := utils.ImageUint64Vec{
		R: decryptedRed,
		G: decryptedGrn,
		B: decryptedBlu,
	}

	// re-construct and save the decrypted Image
	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)
	utils.PostProcessUintImage("pasta2_hhe", "dog.jpg", rows, cols, imgBounds, decryptedImage)

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
