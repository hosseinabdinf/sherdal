package rubato

import (
	"encoding/binary"
	"math"
	sym "sherdal/ske"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
	EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext
	DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext
	GetPrecisionAndLoss(plaintext, decrypted []uint64) (precision float64, lossPercentage float64)
}

type encryptor struct {
	rub *rubato
}

// Encrypt plaintext vector
func (enc *encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	return enc.EncryptWithNonce(plaintext, nil)
}

// EncryptWithNonce encrypts plaintext with a caller-provided nonce seed.
func (enc *encryptor) EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext {
	//logger := utils.NewLogger(utils.DEBUG)
	size := len(plaintext)
	if size == 0 {
		return sym.Ciphertext{}
	}

	modulus := enc.rub.params.GetModulus()
	blockSize := enc.rub.params.GetBlockSize() - 4
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonceSeed := sym.NonceSeed(nonce)
	nonceBuf := make([]byte, sym.NonceSize)
	counter := make([]byte, 8)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := 0; b < numBlock; b++ {
		sym.FillNonce(nonceBuf, nonceSeed, b)
		binary.BigEndian.PutUint64(counter, uint64(b+1))
		keyStream := enc.rub.KeyStream(nonceBuf, counter)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext vector
func (enc *encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	return enc.DecryptWithNonce(ciphertext, nil)
}

// DecryptWithNonce decrypts ciphertext with a caller-provided nonce seed.
func (enc *encryptor) DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext {
	//logger := utils.NewLogger(utils.DEBUG)
	size := len(ciphertext)
	if size == 0 {
		return sym.Plaintext{}
	}

	modulus := enc.rub.params.GetModulus()
	blockSize := enc.rub.params.GetBlockSize() - 4
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonceSeed := sym.NonceSeed(nonce)
	nonceBuf := make([]byte, sym.NonceSize)
	counter := make([]byte, 8)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	for b := 0; b < numBlock; b++ {
		sym.FillNonce(nonceBuf, nonceSeed, b)
		binary.BigEndian.PutUint64(counter, uint64(b+1))
		keyStream := enc.rub.KeyStream(nonceBuf, counter)
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
func (enc *encryptor) GetPrecisionAndLoss(plaintext, decrypted []uint64) (precision float64, lossPercentage float64) {
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

	// Average precision and loss percentage over all elements
	precision = totalPrecision / float64(len(plaintext))
	lossPercentage = totalLoss / float64(len(plaintext))

	return precision, lossPercentage
}
