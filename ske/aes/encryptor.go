package aes

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type Encryptor interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type encryptor struct {
	aes *aesCtr
}

func (enc *encryptor) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	nonceSize := enc.aes.params.GetBlockSize()
	nonce := make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(enc.aes.cipher, nonce)
	ciphertext = make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func (enc *encryptor) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	nonceSize := enc.aes.params.GetBlockSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(ciphertext), nonceSize)
	}

	nonce := ciphertext[:nonceSize]
	encryptedMessage := ciphertext[nonceSize:]

	stream := cipher.NewCTR(enc.aes.cipher, nonce)
	plaintext = make([]byte, len(encryptedMessage))
	stream.XORKeyStream(plaintext, encryptedMessage)

	return plaintext, nil
}
