package hera

type Parameter struct {
	BlockSize int
	Modulus   uint64
	Rounds    int
}

func (params Parameter) GetBlockSize() int {
	return params.BlockSize
}
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}
func (params Parameter) GetRounds() int {
	return params.Rounds
}

// Standard and secure set of parameters for PASTA symmetric cipher
var (
	Hera4Params2816 = Parameter{
		BlockSize: 16,
		Modulus:   268042241, // 28-bit
		Rounds:    4,
	}
	Hera4Params2516 = Parameter{
		BlockSize: 16,
		Modulus:   33292289, // 25-bit
		Rounds:    4,
	}
	Hera5Params2816 = Parameter{
		BlockSize: 16,
		Modulus:   268042241, // 28-bit
		Rounds:    5,
	}
	Hera5Params2516 = Parameter{
		BlockSize: 16,
		Modulus:   33292289, // 25-bit
		Rounds:    5,
	}
)
