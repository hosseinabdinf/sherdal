package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/hosseinabdinf/sherdal/ske"
)

type AESCtr interface {
	NewEncryptor() Encryptor
	KeyStream(nonce []byte) ske.Block
}

type aesCtr struct {
	params    Parameter
	secretKey ske.Key
	cipher    cipher.Block
}

func GenerateSymKey(params Parameter) (key ske.Key) {
	key = make(ske.Key, params.GetKeySize())
	keyBytes := make([]byte, params.GetKeySize())
	_, err := rand.Read(keyBytes)
	if err != nil {
		panic(err)
	}
	for i := 0; i < params.GetKeySize(); i++ {
		key[i] = uint64(keyBytes[i])
	}
	return
}

func NewAESCtr(secretKey ske.Key, params Parameter) (AESCtr, error) {
	if len(secretKey) != params.GetKeySize() {
		return nil, fmt.Errorf("invalid key length: got %d bytes, want %d", len(secretKey), params.GetKeySize())
	}

	secretKeyBytes := make([]byte, params.GetKeySize())
	for i := 0; i < params.GetKeySize(); i++ {
		if secretKey[i] > 0xFF {
			return nil, fmt.Errorf("invalid key byte at index %d: %d", i, secretKey[i])
		}
		secretKeyBytes[i] = byte(secretKey[i])
	}

	cipher, err := aes.NewCipher(secretKeyBytes)
	if err != nil {
		return nil, err
	}

	aes := &aesCtr{
		params:    params,
		secretKey: secretKey,
		cipher:    cipher,
	}
	return aes, nil
}

func (a *aesCtr) NewEncryptor() Encryptor {
	return &encryptor{aes: a}
}

func (a *aesCtr) KeyStream(nonce []byte) ske.Block {
	if len(nonce) != a.params.GetBlockSize() {
		panic("Invalid Nonce Length!")
	}

	// Create a new CTR stream with the given nonce
	stream := cipher.NewCTR(a.cipher, nonce)

	// Generate a keystream block
	keyStreamBlock := make(ske.Block, a.params.GetBlockSize())
	keyStreamBlockBytes := make([]byte, a.params.GetBlockSize())
	stream.XORKeyStream(keyStreamBlockBytes, keyStreamBlockBytes)

	for i := 0; i < a.params.GetBlockSize(); i++ {
		keyStreamBlock[i] = uint64(keyStreamBlockBytes[i])
	}

	return keyStreamBlock
}
