package pasta

// Parameter for Pasta cipher
// note: Plaintext and Ciphertext size are both equal in PASTA, we merge both as BlockSize
type Parameter struct {
	KeySize   int
	BlockSize int
	Rounds    int
	Modulus   uint64
}

// GetKeySize returns the secret key size in bits
func (params Parameter) GetKeySize() int {
	return params.KeySize
}

// GetBlockSize returns the plaintext size in bits
func (params Parameter) GetBlockSize() int {
	return params.BlockSize
}

// GetModulus returns modulus
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}

// GetRounds return rounds
func (params Parameter) GetRounds() int {
	return params.Rounds
}

// Standard and secure set of parameters for PASTA symmetric cipher
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
