package aes

import (
	"bytes"
	"sherdal/hhe/sym"
	"testing"
)

func convertSymBlockToBytes(block sym.Block) []byte {
	byteSlice := make([]byte, len(block))
	for i, v := range block {
		byteSlice[i] = byte(v)
	}
	return byteSlice
}

func TestAESCtrEncryptDecrypt(t *testing.T) {
	params := GetDefaultParams()
	key := GenerateSymKey(params)

	aesCtr, err := NewAESCtr(key, params)
	if err != nil {
		t.Fatalf("Failed to create AES CTR: %v", err)
	}

	encryptor := aesCtr.NewEncryptor()

	plaintext := []byte("This is a test message for AES CTR encryption.")

	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	decryptedText, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Decrypted text does not match original plaintext.\nOriginal: %s\nDecrypted: %s", plaintext, decryptedText)
	} else {
		t.Logf("Decrypted text matches original plaintext.\nOriginal: %s\nDecrypted: %s", plaintext, decryptedText)
	}
}

func TestAESCtrDecryptRejectsShortCiphertext(t *testing.T) {
	params := GetDefaultParams()
	key := GenerateSymKey(params)

	aesCtr, err := NewAESCtr(key, params)
	if err != nil {
		t.Fatalf("Failed to create AES CTR: %v", err)
	}

	encryptor := aesCtr.NewEncryptor()
	_, err = encryptor.Decrypt([]byte("short"))
	if err == nil {
		t.Fatal("expected an error for short ciphertext")
	}
}

func TestNewAESCtrRejectsOversizedKeyValues(t *testing.T) {
	params := GetDefaultParams()
	key := GenerateSymKey(params)
	key[0] = 256

	_, err := NewAESCtr(key, params)
	if err == nil {
		t.Fatal("expected an error for invalid key byte value")
	}
}

func TestAESCtrKeyStream(t *testing.T) {
	params := GetDefaultParams()
	key := GenerateSymKey(params)

	aesCtr, err := NewAESCtr(key, params)
	if err != nil {
		t.Fatalf("Failed to create AES CTR: %v", err)
	}

	nonce1 := make([]byte, params.GetBlockSize())
	// For testing, let's use a fixed nonce for predictability
	nonce1[0] = 1

	nonce2 := make([]byte, params.GetBlockSize())
	nonce2[0] = 1 // Same nonce as nonce1

	nonce3 := make([]byte, params.GetBlockSize())
	nonce3[0] = 2 // Different nonce

	keyStream1 := aesCtr.KeyStream(nonce1)
	keyStream2 := aesCtr.KeyStream(nonce2)
	keyStream3 := aesCtr.KeyStream(nonce3)

	// Keystreams generated with the same key and nonce should be identical
	if !bytes.Equal(convertSymBlockToBytes(keyStream1), convertSymBlockToBytes(keyStream2)) {
		t.Errorf("Keystreams with same nonce are not equal.\nKeystream 1: %v\nKeystream 2: %v", keyStream1, keyStream2)
	}

	// Keystreams generated with different nonces should be different
	if bytes.Equal(convertSymBlockToBytes(keyStream1), convertSymBlockToBytes(keyStream3)) {
		t.Errorf("Keystreams with different nonces are equal.\nKeystream 1: %v\nKeystream 3: %v", keyStream1, keyStream3)
	}
}
