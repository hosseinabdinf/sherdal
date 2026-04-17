package hera

import (
	sym "sherdal/ske"
	"sherdal/utils"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
	KeyStream(size int) sym.Matrix
	EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext
	DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext
	KeyStreamWithNonce(size int, nonce []byte) sym.Matrix
}

type encryptor struct {
	her *hera
}

// Encrypt plaintext
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

	modulus := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonceSeed := sym.NonceSeed(nonce)
	nonceBuf := make([]byte, sym.NonceSize)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := 0; b < numBlock; b++ {
		sym.FillNonce(nonceBuf, nonceSeed, b)
		keyStream := enc.her.KeyStream(nonceBuf)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext
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

	modulus := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonceSeed := sym.NonceSeed(nonce)
	nonceBuf := make([]byte, sym.NonceSize)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	for b := 0; b < numBlock; b++ {
		sym.FillNonce(nonceBuf, nonceSeed, b)
		keyStream := enc.her.KeyStream(nonceBuf)
		for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
			if keyStream[i-b*blockSize] > plaintext[i] {
				plaintext[i] += modulus
			}
			plaintext[i] = plaintext[i] - keyStream[i-b*blockSize]
		}
	}

	return plaintext
}

// KeyStream takes len(plaintext) as input and generate a KeyStream
func (enc *encryptor) KeyStream(size int) (keyStream sym.Matrix) {
	return enc.KeyStreamWithNonce(size, nil)
}

// KeyStreamWithNonce takes len(plaintext) as input and generates a keyed stream matrix.
func (enc *encryptor) KeyStreamWithNonce(size int, nonce []byte) (keyStream sym.Matrix) {
	logger := utils.NewLogger(utils.DEBUG)

	blockSize := enc.her.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonceSeed := sym.NonceSeed(nonce)
	nonceBuf := make([]byte, sym.NonceSize)

	keyStream = make(sym.Matrix, numBlock)
	for b := 0; b < numBlock; b++ {
		sym.FillNonce(nonceBuf, nonceSeed, b)
		keyStream[b] = enc.her.KeyStream(nonceBuf)
	}

	logger.PrintSummarizedMatrix("keystream", sym.MatrixToInterfaceMat(keyStream), numBlock, blockSize)
	return
}
