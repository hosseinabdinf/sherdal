package aes

import (
	"crypto/cipher"
	"crypto/rand"
)

type Encryptor interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte)
}

type encryptor struct {
	aes aesCtr
}

func (enc *encryptor) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	// Generate a random nonce
	nonce := make([]byte, enc.aes.params.GetBlockSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Create a new CTR stream with the generated nonce
	stream := cipher.NewCTR(enc.aes.cipher, nonce)

	// Encrypt the plaintext
	ciphertext = make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func (enc *encryptor) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	// Extract the nonce from the ciphertext
	nonce := ciphertext[:enc.aes.params.GetBlockSize()]
	encryptedMessage := ciphertext[enc.aes.params.GetBlockSize():]

	// Create a new CTR stream with the extracted nonce
	stream := cipher.NewCTR(enc.aes.cipher, nonce)

	// Decrypt the ciphertext
	plaintext = make([]byte, len(encryptedMessage))
	stream.XORKeyStream(plaintext, encryptedMessage)

	return plaintext, nil
}
