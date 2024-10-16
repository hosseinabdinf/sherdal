package rubato

type Parameter struct {
	LogN      int
	BlockSize int
	Modulus   uint64
	Rounds    int
	Sigma     float64
}

func (params Parameter) GetLogN() int {
	return params.LogN
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
func (params Parameter) GetSigma() float64 {
	return params.Sigma
}

var (
	// Rubato5Param2616 for Rubato 128S
	Rubato5Param2616 = Parameter{
		LogN:      16,
		BlockSize: 16,
		Modulus:   0x3ee0001,
		Rounds:    5,
		Sigma:     4.1888939442150431183694336293110096189965156272318139054922212,
	}
	// Rubato3Param2516 for Rubato 128M
	Rubato3Param2516 = Parameter{
		LogN:      16,
		BlockSize: 36,
		Modulus:   0x1fc0001,
		Rounds:    3,
		Sigma:     1.6356633496458739795537788457309656607510203877762320964302959,
	}
	// Rubato2Param2516 for Rubato 128L
	Rubato2Param2516 = Parameter{
		LogN:      16,
		BlockSize: 64,
		Modulus:   0x1fc0001,
		Rounds:    2,
		Sigma:     1.6356633496458739795537788457309656607510203877762320964302959,
	}
)
