package hhe

import (
	"github.com/hosseinabdinf/sherdal/ske"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// SymmetricParams defines the shared interface for symmetric cipher parameters.
type SymmetricParams interface {
	GetBlockSize() int
	GetModulus() uint64
	GetRounds() int
}

// SymmetricCipher defines the interface for symmetric encryption/decryption.
type SymmetricCipher interface {
	Encrypt(plaintext ske.Plaintext) ske.Ciphertext
	Decrypt(ciphertext ske.Ciphertext) ske.Plaintext
	// KeyStream returns the keystream blocks for the given number of items.
	KeyStream(size int) ske.Matrix
}

// HomomorphicEvaluator defines a unified interface for homomorphic evaluation of symmetric primitives.
type HomomorphicEvaluator interface {
	// Crypt performs the homomorphic transciphering (evaluation of symmetric decryption).
	// nonces: bitsliced or formatted nonces for each slot.
	// keyEnc: encrypted symmetric key ciphertexts.
	Crypt(nonces [][]byte, keyEnc []*rlwe.Ciphertext) []*rlwe.Ciphertext
}
