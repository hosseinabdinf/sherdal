package hera

import (
	"encoding/binary"
	"math"
	"sherdal/hhe/sym"
	"sherdal/utils"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
	KeyStream(size int) sym.Matrix
}

type encryptor struct {
	her hera
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(plaintext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for i := 0; i < numBlock; i++ {
		z := make(sym.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))
		ciphertext[i] = (ciphertext[i] + z[i]) % modulus
	}

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)

	var size = len(ciphertext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	for i := 0; i < numBlock; i++ {
		z := make(sym.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))

		if z[i] > plaintext[i] {
			plaintext[i] += modulus
		}
		plaintext[i] = plaintext[i] - z[i]
	}

	return plaintext
}

// KeyStream takes len(plaintext) as input and generate a KeyStream
func (enc encryptor) KeyStream(size int) (keyStream sym.Matrix) {
	logger := utils.NewLogger(utils.DEBUG)

	blockSize := enc.her.params.GetBlockSize()
	numBlock := int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	// generate key stream
	keyStream = make(sym.Matrix, numBlock)
	for i := 0; i < numBlock; i++ {
		copy(keyStream[i], enc.her.KeyStream(nonces[i]))
	}

	logger.PrintSummarizedMatrix("keystream", utils.ConvertMatToInterfaceMat(keyStream), numBlock, blockSize)
	return
}
