package pasta

import (
	"encoding/binary"
	"sherdal/hhe/sym"
	"sherdal/utils"
)

type Encryptor interface {
	Encrypt(plaintext sym.Plaintext) sym.Ciphertext
	Decrypt(ciphertext sym.Ciphertext) sym.Plaintext
	EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext
	DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext
}

type encryptor struct {
	pas *pasta
}

// Encrypt plaintext vector
func (enc *encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	return enc.EncryptWithNonce(plaintext, nil)
}

// EncryptWithNonce encrypts plaintext with caller-provided nonce.
func (enc *encryptor) EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext {
	logger := utils.NewLogger(utils.DEBUG)
	size := len(plaintext)
	if size == 0 {
		return sym.Ciphertext{}
	}

	modulus := enc.pas.params.GetModulus()
	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	nonce = sym.NormalizeNonce(nonce)
	counter := make([]byte, 8)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	for b := 0; b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, uint64(b))
		keyStream := enc.pas.KeyStream(nonce, counter)
		logger.PrintSummarizedVector("keystream", keyStream, len(keyStream))
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

// DecryptWithNonce decrypts ciphertext with caller-provided nonce.
func (enc *encryptor) DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext {
	//logger := utils.NewLogger(utils.DEBUG)
	size := len(ciphertext)
	if size == 0 {
		return sym.Plaintext{}
	}

	modulus := enc.pas.params.GetModulus()
	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	//logger.PrintFormatted("Number of Block: %d", numBlock)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	nonce = sym.NormalizeNonce(nonce)
	counter := make([]byte, 8)

	for b := 0; b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, uint64(b))
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
