package rubato

import (
	"encoding/binary"
	"math"
	"sherdal/hhe/sym"
	"sherdal/utils"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
	GetPrecisionAndLoss(plaintext, decrypted []uint64) (precision float64, lossPercentage float64)
}

type encryptor struct {
	rub rubato
}

// Encrypt plaintext vector
func (enc encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(plaintext)
	var modulus = enc.rub.params.GetModulus()
	var blockSize = enc.rub.params.GetBlockSize() - 4
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
	counter := make([]byte, 8)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := 0; b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, uint64(b+1))
		keyStream := make(sym.Block, blockSize)
		copy(keyStream, enc.rub.KeyStream(nonces[b], counter))
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext vector
func (enc encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = len(ciphertext)
	var modulus = enc.rub.params.GetModulus()
	var blockSize = enc.rub.params.GetBlockSize() - 4
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
	counter := make([]byte, 8)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	for b := 0; b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, uint64(b+1))
		keyStream := make(sym.Block, blockSize)
		copy(keyStream, enc.rub.KeyStream(nonces[b], counter))
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			if keyStream[i-b*blockSize] > plaintext[i] {
				plaintext[i] += modulus
			}
			plaintext[i] = plaintext[i] - keyStream[i-b*blockSize]
		}
	}

	return plaintext
}

// GetPrecisionAndLoss return the average precision and lost percentage
// we have a small data loss in Rubato because of adding Gaussian Noise
// during the encryption
func (enc encryptor) GetPrecisionAndLoss(plaintext, decrypted []uint64) (precision float64, lossPercentage float64) {
	if len(plaintext) != len(decrypted) {
		panic("plaintext and decrypted slices must have the same length")
	}

	var totalPrecision float64
	var totalLoss float64

	for i := range plaintext {
		diff := float64(decrypted[i]) - float64(plaintext[i])

		if plaintext[i] != 0 {
			totalPrecision += (1 - (diff / float64(plaintext[i]))) * 100
		} else {
			totalPrecision += 100
		}

		totalLoss += (diff / float64(plaintext[i])) * 100
	}

	// Average precision and loss percentage over all elements
	precision = totalPrecision / float64(len(plaintext))
	lossPercentage = totalLoss / float64(len(plaintext))

	return precision, lossPercentage
}
