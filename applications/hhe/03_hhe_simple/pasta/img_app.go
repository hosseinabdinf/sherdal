package pasta

import (
	"encoding/binary"
	"image"
	"math"
	"math/bits"
	"sync"

	"github.com/hosseinabdinf/sherdal/hhe/pasta"

	"github.com/hosseinabdinf/sherdal/ske"
	pasta2 "github.com/hosseinabdinf/sherdal/ske/pasta"
	"github.com/hosseinabdinf/sherdal/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

func HHEImgEncApp(imgBounds image.Rectangle, img utils.ImageUint64Vec) {
	logger := utils.NewLogger(utils.DEBUG)

	symParams := pasta2.Pasta4Param3215

	cfg := pasta.Config{
		Preset:          pasta.Pasta3_3215,
		BGVLogN:         15,
		SymmetricParams: symParams,
	}

	fvPastaRed, err := pasta.NewPasta(cfg)
	if err != nil {
		panic(err)
	}
	fvPastaGrn, err := pasta.NewPasta(cfg)
	if err != nil {
		panic(err)
	}
	fvPastaBlu, err := pasta.NewPasta(cfg)
	if err != nil {
		panic(err)
	}

	key := pasta2.GenerateSymKey(symParams)

	if err := fvPastaRed.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvPastaGrn.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}
	if err := fvPastaBlu.EncryptSymmetricKey(key); err != nil {
		panic(err)
	}

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
		redCipher = encryptWithHheCounters(key, img.R, nonce, symParams)
	}()
	go func() {
		defer encWg.Done()
		grnCipher = encryptWithHheCounters(key, img.G, nonce, symParams)
	}()
	go func() {
		defer encWg.Done()
		bluCipher = encryptWithHheCounters(key, img.B, nonce, symParams)
	}()
	encWg.Wait()
	logger.PrintMemUsage("PastaEncryption")

	// Transcipher channels concurrently using their own Pasta instances to prevent evaluator data races
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

	// Decrypt channels concurrently using their own Pasta instances
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
	logger.PrintMemUsage("PastaDecryption")

	decryptedVec := utils.ImageUint64Vec{
		R: decryptedRed,
		G: decryptedGrn,
		B: decryptedBlu,
	}

	// re-construct and save the decrypted Image
	decryptedImage := utils.NewImg64Mat(decryptedVec, rows, cols)
	utils.PostProcessUintImage("pasta_hhe", "dog.jpg", rows, cols, imgBounds, decryptedImage)

	logger.PrintSummarizedMatrix("Original", utils.VecToInterfaceMat(img.R), rows, cols)
	logger.PrintSummarizedMatrix("Decrypted", utils.VecToInterfaceMat(decryptedVec.R), rows, cols)

	precision, lost := getPrecisionAndLoss(img.R, decryptedVec.R)
	logger.PrintFormatted("Precision= %f, Lost= %f", precision, lost)
}

func encryptWithHheCounters(key []uint64, plaintext ske.Plaintext, nonce []byte, params pasta2.Parameter) ske.Ciphertext {
	size := len(plaintext)
	if size == 0 {
		return ske.Ciphertext{}
	}

	modulus := params.GetModulus()
	blockSize := params.GetBlockSize()
	numBlock := ske.CeilDiv(size, blockSize)
	rounds := params.GetRounds()

	nonce = ske.NormalizeNonce(nonce)

	ciphertext := make(ske.Ciphertext, size)
	copy(ciphertext, plaintext)

	nonceSeed := ske.NonceSeed(nonce)

	for b := 0; b < numBlock; b++ {
		// 1. Seed SHAKE128
		nonceBuf := make([]byte, ske.NonceSize)
		ske.FillNonce(nonceBuf, nonceSeed, b)

		shake := sha3.NewShake128()
		_, _ = shake.Write(nonceBuf)
		counter := make([]byte, 8)
		binary.BigEndian.PutUint64(counter, uint64(b+1))
		_, _ = shake.Write(counter)

		// 2. Sample round constants
		rc := make([][]uint64, rounds+1)
		for r := 0; r <= rounds; r++ {
			rc[r] = make([]uint64, 2*blockSize)
			for s := 0; s < 2*blockSize; s++ {
				rc[r][s] = utils.SampleZqx(shake, modulus)
			}
		}

		// 3. Sample companion matrices
		mat1 := make([][][]uint64, rounds+1)
		mat2 := make([][][]uint64, rounds+1)
		for r := 0; r <= rounds; r++ {
			// mat1
			firstRow1 := make([]uint64, blockSize)
			for col := 0; col < blockSize; col++ {
				firstRow1[col] = utils.SampleZqx(shake, modulus)
			}
			mat1[r] = make([][]uint64, blockSize)
			mat1[r][0] = firstRow1
			for row := 1; row < blockSize; row++ {
				mat1[r][row] = pastaCalculateRow(mat1[r][row-1], firstRow1, modulus)
			}

			// mat2
			firstRow2 := make([]uint64, blockSize)
			for col := 0; col < blockSize; col++ {
				firstRow2[col] = utils.SampleZqx(shake, modulus)
			}
			mat2[r] = make([][]uint64, blockSize)
			mat2[r][0] = firstRow2
			for row := 1; row < blockSize; row++ {
				mat2[r][row] = pastaCalculateRow(mat2[r][row-1], firstRow2, modulus)
			}
		}

		// 4. Initialize state
		state1 := make([]uint64, blockSize)
		state2 := make([]uint64, blockSize)
		copy(state1, key[:blockSize])
		copy(state2, key[blockSize:])

		// 5. Round 0: Initial linear layer
		state1 = matmul(mat1[0], state1, modulus)
		state1 = addRC(state1, rc[0][:blockSize], modulus)
		state2 = matmul(mat2[0], state2, modulus)
		state2 = addRC(state2, rc[0][blockSize:], modulus)
		state1, state2 = mix(state1, state2, modulus)

		// 6. Rounds 1..rounds-1
		for round := 1; round < rounds; round++ {
			combinedState := make([]uint64, 2*blockSize)
			copy(combinedState[:blockSize], state1)
			copy(combinedState[blockSize:], state2)

			combinedState = sBoxFeistelEntire(combinedState, modulus)

			copy(state1, combinedState[:blockSize])
			copy(state2, combinedState[blockSize:])

			state1 = matmul(mat1[round], state1, modulus)
			state1 = addRC(state1, rc[round][:blockSize], modulus)
			state2 = matmul(mat2[round], state2, modulus)
			state2 = addRC(state2, rc[round][blockSize:], modulus)
			state1, state2 = mix(state1, state2, modulus)
		}

		// 7. Final S-box: cube
		state1 = sBoxCube(state1, modulus)
		state2 = sBoxCube(state2, modulus)

		// 8. Final linear layer
		state1 = matmul(mat1[rounds], state1, modulus)
		state1 = addRC(state1, rc[rounds][:blockSize], modulus)
		state2 = matmul(mat2[rounds], state2, modulus)
		state2 = addRC(state2, rc[rounds][blockSize:], modulus)
		state1, state2 = mix(state1, state2, modulus)

		// 9. Keystream for this block is state1
		keyStream := state1

		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

func sBoxFeistelEntire(state []uint64, modulus uint64) []uint64 {
	ps := len(state)
	nState := make([]uint64, ps)
	nState[0] = state[0]
	for i := 1; i < ps; i++ {
		prevState := state[i-1]
		square := mulMod(prevState, prevState, modulus)
		nState[i] = addMod(square, state[i], modulus)
	}
	return nState
}

func sBoxCube(state []uint64, modulus uint64) []uint64 {
	ps := len(state)
	nState := make([]uint64, ps)
	for i := 0; i < ps; i++ {
		val := state[i]
		square := mulMod(val, val, modulus)
		nState[i] = mulMod(square, val, modulus)
	}
	return nState
}

func matmul(mat [][]uint64, state []uint64, modulus uint64) []uint64 {
	ps := len(state)
	nState := make([]uint64, ps)
	for i := 0; i < ps; i++ {
		for j := 0; j < ps; j++ {
			matMulVal := mulMod(mat[i][j], state[j], modulus)
			nState[i] = addMod(nState[i], matMulVal, modulus)
		}
	}
	return nState
}

func addRC(state []uint64, rc []uint64, modulus uint64) []uint64 {
	ps := len(state)
	nState := make([]uint64, ps)
	for i := 0; i < ps; i++ {
		nState[i] = addMod(state[i], rc[i], modulus)
	}
	return nState
}

func mix(state1, state2 []uint64, modulus uint64) ([]uint64, []uint64) {
	ps := len(state1)
	nState1 := make([]uint64, ps)
	nState2 := make([]uint64, ps)
	for i := 0; i < ps; i++ {
		st1 := state1[i]
		st2 := state2[i]

		sum := addMod(st1, st2, modulus)
		nState1[i] = addMod(sum, st1, modulus)
		nState2[i] = addMod(sum, st2, modulus)
	}
	return nState1, nState2
}

func pastaCalculateRow(prevRow, firstRow []uint64, modulus uint64) []uint64 {
	T := len(prevRow)
	out := make([]uint64, T)
	last := prevRow[T-1]

	for i := 0; i < T; i++ {
		tmp := mulMod(firstRow[i], last, modulus)
		if i > 0 {
			tmp = addMod(tmp, prevRow[i-1], modulus)
		}
		out[i] = tmp
	}
	return out
}

func mulMod(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, m)
	return rem
}

func addMod(a, b, m uint64) uint64 {
	res := a + b
	if res >= m {
		res -= m
	}
	return res
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
