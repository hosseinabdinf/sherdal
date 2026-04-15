package aes

import (
	"sherdal/hhe/sym"
	"testing"
)

func BenchmarkAESCtr(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	params := GetDefaultParams()
	plaintext := []byte("This is a benchmark message for AES CTR encryption and decryption.")
	nonce := make([]byte, params.GetBlockSize())

	var key sym.Key
	b.Run("AES/SymKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key = GenerateSymKey(params)
		}
	})

	key = GenerateSymKey(params)

	var aesCtr AESCtr
	b.Run("AES/NewAESCtr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var err error
			aesCtr, err = NewAESCtr(key, params)
			if err != nil {
				b.Fatalf("failed to create AES CTR: %v", err)
			}
		}
	})

	aesCtr, err := NewAESCtr(key, params)
	if err != nil {
		b.Fatalf("failed to create AES CTR: %v", err)
	}

	var encryptor Encryptor
	b.Run("AES/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = aesCtr.NewEncryptor()
		}
	})

	encryptor = aesCtr.NewEncryptor()

	var ciphertext []byte
	b.Run("AES/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var err error
			ciphertext, err = encryptor.Encrypt(plaintext)
			if err != nil {
				b.Fatalf("failed to encrypt plaintext: %v", err)
			}
		}
	})

	ciphertext, err = encryptor.Encrypt(plaintext)
	if err != nil {
		b.Fatalf("failed to encrypt plaintext: %v", err)
	}

	b.Run("AES/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				b.Fatalf("failed to decrypt ciphertext: %v", err)
			}
		}
	})

	b.Run("AES/KeyStream", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = aesCtr.KeyStream(nonce)
		}
	})
}
