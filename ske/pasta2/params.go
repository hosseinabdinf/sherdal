package pasta2

import (
	"fmt"
	"math/bits"

	utilsmath "github.com/hosseinabdinf/sherdal/utils/math"
)

// Mode represents the Pasta2 execution mode
type Mode int

const (
	// ModeSpecStrict strictly follows the Pasta2 specification
	ModeSpecStrict Mode = iota
	// ModeCompatCPP maintains compatibility with the C++ implementation
	ModeCompatCPP
)

// Parameter for Pasta v2. KeySize is 2*BlockSize field words.
type Parameter struct {
	KeySize   int
	BlockSize int
	Rounds    int
	Modulus   uint64
	Mode      Mode
}

// GetKeySize returns the secret key size in bits/words
func (params Parameter) GetKeySize() int {
	return params.KeySize
}

// GetBlockSize returns the plaintext size in bits/words
func (params Parameter) GetBlockSize() int {
	return params.BlockSize
}

// GetRounds returns the number of rounds
func (params Parameter) GetRounds() int {
	return params.Rounds
}

// GetModulus returns the prime modulus
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}

// GetMode returns the Pasta2 mode
func (params Parameter) GetMode() Mode {
	return params.Mode
}

// Validate validates that the parameters are valid and secure for Pasta2
func (params Parameter) Validate() error {
	if params.BlockSize <= 0 {
		return fmt.Errorf("invalid block size: got %d, want > 0", params.BlockSize)
	}
	if params.Rounds < 1 {
		return fmt.Errorf("invalid rounds: got %d, want >= 1", params.Rounds)
	}
	if params.KeySize != 2*params.BlockSize {
		return fmt.Errorf("invalid key size: got %d, want %d", params.KeySize, 2*params.BlockSize)
	}
	if params.Modulus <= 65536 {
		return fmt.Errorf("invalid modulus: got %d, want > 65536", params.Modulus)
	}
	if bits.Len64(params.Modulus) > 60 {
		return fmt.Errorf("invalid modulus: got %d-bit modulus, want at most 60 bits", bits.Len64(params.Modulus))
	}
	if !utilsmath.IsPrime(params.Modulus) {
		return fmt.Errorf("invalid modulus: %d is not prime", params.Modulus)
	}
	if utilsmath.GCD(params.Modulus-1, 3) != 1 {
		return fmt.Errorf("invalid modulus: gcd(p-1, 3) must be 1")
	}
	switch params.Mode {
	case ModeSpecStrict, ModeCompatCPP:
		return nil
	default:
		return fmt.Errorf("invalid mode: %d", params.Mode)
	}
}

var (
	Pasta3Param1614 = Parameter{
		Rounds:    3,
		KeySize:   256,
		BlockSize: 128,
		Modulus:   65537,
	}
	Pasta3Param3215 = Parameter{
		Rounds:    3,
		KeySize:   256,
		BlockSize: 128,
		Modulus:   8088322049,
	}
	Pasta3Param6015 = Parameter{
		Rounds:    3,
		KeySize:   256,
		BlockSize: 128,
		Modulus:   1096486890805657601,
	}
	Pasta4Param1614 = Parameter{
		Rounds:    4,
		KeySize:   64,
		BlockSize: 32,
		Modulus:   65537,
	}
	Pasta4Param3215 = Parameter{
		Rounds:    4,
		KeySize:   64,
		BlockSize: 32,
		Modulus:   8088322049,
	}
	Pasta4Param6015 = Parameter{
		Rounds:    4,
		KeySize:   64,
		BlockSize: 32,
		Modulus:   1096486890805657601,
	}
)
