package hera

import (
	"sync"

	sym "github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/utils"
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
	size := len(plaintext)
	if size == 0 {
		return sym.Ciphertext{}
	}

	modulus := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)

	nonceSeed := sym.NonceSeed(nonce)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			nonceBuf := make([]byte, sym.NonceSize)
			sym.FillNonce(nonceBuf, nonceSeed, b)
			herClone := enc.her.runtime()
			keyStream := herClone.KeyStream(nonceBuf)
			for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
				ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
			}
		}(b)
	}
	wg.Wait()

	return ciphertext
}

// Decrypt ciphertext
func (enc *encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	return enc.DecryptWithNonce(ciphertext, nil)
}

// DecryptWithNonce decrypts ciphertext with a caller-provided nonce seed.
func (enc *encryptor) DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext {
	size := len(ciphertext)
	if size == 0 {
		return sym.Plaintext{}
	}

	modulus := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)

	nonceSeed := sym.NonceSeed(nonce)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			nonceBuf := make([]byte, sym.NonceSize)
			sym.FillNonce(nonceBuf, nonceSeed, b)
			herClone := enc.her.runtime()
			keyStream := herClone.KeyStream(nonceBuf)
			for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
				val := plaintext[i]
				ks := keyStream[i-b*blockSize]
				if ks > val {
					val += modulus
				}
				plaintext[i] = val - ks
			}
		}(b)
	}
	wg.Wait()

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

	nonceSeed := sym.NonceSeed(nonce)

	keyStream = make(sym.Matrix, numBlock)
	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			nonceBuf := make([]byte, sym.NonceSize)
			sym.FillNonce(nonceBuf, nonceSeed, b)
			herClone := enc.her.runtime()
			keyStream[b] = herClone.KeyStream(nonceBuf)
		}(b)
	}
	wg.Wait()

	logger.PrintSummarizedMatrix("keystream", sym.MatrixToInterfaceMat(keyStream), numBlock, blockSize)
	return
}
