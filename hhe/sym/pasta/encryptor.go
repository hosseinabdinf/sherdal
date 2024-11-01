package pasta

import (
	"encoding/binary"
	"math"
	"sherdal/hhe/sym"
	"sherdal/utils"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
}

type encryptor struct {
	pas pasta
}

// Encrypt plaintext vector
func (enc encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = uint64(len(plaintext))
	var modulus = enc.pas.params.GetModulus()
	var blockSize = uint64(enc.pas.params.GetBlockSize())
	var numBlock = uint64(math.Ceil(float64(size / blockSize)))
	if size <= blockSize {
		diff := int(blockSize - size)
		numBlock = uint64(1)
		for i := 0; i < diff; i++ {
			plaintext = append(plaintext, 0)
		}
		size = uint64(len(plaintext))
	}
	logger.PrintFormatted("Number of Block: %d", numBlock)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		logger.PrintSummarizedVector("keystream", keyStream, len(keyStream))
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext vector
func (enc encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	logger := utils.NewLogger(utils.DEBUG)
	var size = uint64(len(ciphertext))
	var modulus = enc.pas.params.GetModulus()
	var blockSize = uint64(enc.pas.params.GetBlockSize())
	var numBlock = uint64(math.Ceil(float64(size / blockSize)))
	if size < blockSize {
		panic("The length of ciphertext does not match the block size!")
	}
	logger.PrintFormatted("Number of Block: %d", numBlock)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			if keyStream[i-b*blockSize] > plaintext[i] {
				plaintext[i] += modulus
			}
			plaintext[i] = plaintext[i] - keyStream[i-b*blockSize]
		}
	}

	return plaintext
}
