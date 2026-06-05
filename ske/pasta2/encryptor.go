package pasta2

import (
	"encoding/binary"
	"fmt"
	"sync"

	sym "github.com/hosseinabdinf/sherdal/ske"
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
	pas *pasta2
}

func (enc *encryptor) Encrypt(plaintext sym.Plaintext) sym.Ciphertext {
	return enc.EncryptWithNonce(plaintext, nil)
}

func (enc *encryptor) EncryptWithNonce(plaintext sym.Plaintext, nonce []byte) sym.Ciphertext {
	if err := enc.validateWords(plaintext, "plaintext"); err != nil {
		panic(err)
	}
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
			counter := make([]byte, sym.NonceSize)
			binary.BigEndian.PutUint64(counter, uint64(b))
			pasClone := enc.pas.runtime()
			keyStream := pasClone.KeyStream(nonce, counter)
			for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
				j := i - b*blockSize
				ciphertext[i] = pasClone.add(ciphertext[i], keyStream[j])
				if ciphertext[i] >= modulus {
					panic("internal modular addition error")
				}
			}
		}(b)
	}
	wg.Wait()
	return ciphertext
}

func (enc *encryptor) Decrypt(ciphertext sym.Ciphertext) sym.Plaintext {
	return enc.DecryptWithNonce(ciphertext, nil)
}

func (enc *encryptor) DecryptWithNonce(ciphertext sym.Ciphertext, nonce []byte) sym.Plaintext {
	if err := enc.validateWords(ciphertext, "ciphertext"); err != nil {
		panic(err)
	}
	size := len(ciphertext)
	if size == 0 {
		return sym.Plaintext{}
	}

	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	nonce = sym.NormalizeNonce(nonce)

	plaintext := make(sym.Plaintext, size)
	copy(plaintext, ciphertext)

	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			counter := make([]byte, sym.NonceSize)
			binary.BigEndian.PutUint64(counter, uint64(b))
			pasClone := enc.pas.runtime()
			keyStream := pasClone.KeyStream(nonce, counter)
			for i := b * blockSize; i < (b+1)*blockSize && i < size; i++ {
				j := i - b*blockSize
				plaintext[i] = pasClone.sub(plaintext[i], keyStream[j])
			}
		}(b)
	}
	wg.Wait()
	return plaintext
}

func (enc *encryptor) KeyStream(size int) sym.Matrix {
	return enc.KeyStreamWithNonce(size, nil)
}

func (enc *encryptor) KeyStreamWithNonce(size int, nonce []byte) sym.Matrix {
	if size <= 0 {
		return sym.Matrix{}
	}
	blockSize := enc.pas.params.GetBlockSize()
	numBlock := sym.CeilDiv(size, blockSize)
	nonce = sym.NormalizeNonce(nonce)

	keyStream := make(sym.Matrix, numBlock)
	var wg sync.WaitGroup
	for b := 0; b < numBlock; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			counter := make([]byte, sym.NonceSize)
			binary.BigEndian.PutUint64(counter, uint64(b))
			pasClone := enc.pas.runtime()
			keyStream[b] = pasClone.KeyStream(nonce, counter)
		}(b)
	}
	wg.Wait()
	return keyStream
}

func (enc *encryptor) validateWords(words []uint64, label string) error {
	modulus := enc.pas.params.GetModulus()
	for i, v := range words {
		if v >= modulus {
			return fmt.Errorf("invalid %s word at index %d: got %d, want < %d", label, i, v, modulus)
		}
	}
	return nil
}
