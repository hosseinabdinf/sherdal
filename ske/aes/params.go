package aes

import (
	"fmt"
	"sherdal/ske"
)

type Parameter interface {
	GetBlockSize() int
	GetKeySize() int
}

type parameter struct {
	BlockSize int
	KeySize   int
}

// GetBlockSize returns the block size of the symmetric cipher.
func (p parameter) GetBlockSize() int {
	return p.BlockSize
}

// GetKeySize returns the key size of the symmetric cipher.
func (p parameter) GetKeySize() int {
	return p.KeySize
}

// GetDefaultParams returns the default parameters for AES CTR.
func GetDefaultParams() Parameter {
	return &parameter{
		BlockSize: 16, // AES block size is 128 bits (16 bytes)
		KeySize:   32, // AES-256 key size is 256 bits (32 bytes)
	}
}

// GenSymParameters generates a new set of parameters for the symmetric cipher.
func GenSymParameters(blockSize, keySize int) (Parameter, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid key size: %d, must be 16, 24, or 32 bytes", keySize)
	}

	if blockSize != 16 {
		return nil, fmt.Errorf("invalid block size: %d, must be 16 bytes for AES", blockSize)
	}

	return &parameter{BlockSize: blockSize, KeySize: keySize}, nil
}

// GenCiphertextCapacity returns the number of ciphertexts required to encrypt n values
func (p parameter) GenCiphertextCapacity(n int) (num int) {
	return ske.CeilDiv(n, p.BlockSize)
}
