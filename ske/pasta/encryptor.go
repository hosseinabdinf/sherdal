package pasta

import (
	"encoding/binary"
	"sync"

	sym "github.com/hosseinabdinf/sherdal/ske"
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
	size := len(plaintext)
	if size == 0 {
		return sym.Ciphertext{}
	}

	modulus := enc.pas.params.GetModulus()
	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)

	nonce = sym.NormalizeNonce(nonce)

	ciphertext := make(sym.Ciphertext, size)
	copy(ciphertext, plaintext)

	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, uint64(b))
			pasClone := enc.pas.runtime()
			keyStream := pasClone.KeyStream(nonce, counter)
			for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
				ciphertext[i] = (ciphertext[i] + keyStream[i-b*blockSize]) % modulus
			}
		}(b)
	}
	wg.Wait()

	return ciphertext
}

// Decrypt ciphertext vector
func (enc *encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	return enc.DecryptWithNonce(ciphertext, nil)
}

// DecryptWithNonce decrypts ciphertext with caller-provided nonce.
func (enc *encryptor) DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext {
	size := len(ciphertext)
	if size == 0 {
		return sym.Plaintext{}
	}

	modulus := enc.pas.params.GetModulus()
	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	nonce = sym.NormalizeNonce(nonce)

	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, uint64(b))
			pasClone := enc.pas.runtime()
			keyStream := pasClone.KeyStream(nonce, counter)
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
