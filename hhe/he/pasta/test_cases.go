package pasta

import (
	"math"
	symPasta "sherdal/hhe/sym/pasta"
)

type TestContext struct {
	Params    Parameter
	SymParams symPasta.Parameter
}

// Decryption Test Vectors
var pasta3TestVector = []TestContext{
	{
		Params: Parameter{
			UseBsGs:   true,
			bSgSN1:    16,
			bSgSN2:    8,
			logN:      14,
			plainMod:  65537,
			modDegree: uint64(math.Pow(2, 14)),
		},
		SymParams: symPasta.Pasta3Param1614,
	},
	{
		Params: Parameter{
			UseBsGs:   true,
			bSgSN1:    16,
			bSgSN2:    8,
			logN:      15,
			plainMod:  8088322049,
			modDegree: uint64(math.Pow(2, 15)),
		},
		SymParams: symPasta.Pasta3Param3215,
	},
	{
		Params: Parameter{
			UseBsGs:   true,
			logN:      15,
			bSgSN1:    16,
			bSgSN2:    8,
			plainMod:  1096486890805657601,
			modDegree: uint64(math.Pow(2, 15)),
		},
		SymParams: symPasta.Pasta3Param6015,
	},
}

var pasta4TestVector = []TestContext{
	{
		Params: Parameter{
			UseBsGs:   true,
			bSgSN1:    8,
			bSgSN2:    4,
			logN:      14,
			plainMod:  65537,
			modDegree: uint64(math.Pow(2, 14)),
		},
		SymParams: symPasta.Pasta4Param1614,
	},
	{
		Params: Parameter{
			UseBsGs:   true,
			bSgSN1:    8,
			bSgSN2:    4,
			logN:      15,
			plainMod:  8088322049,
			modDegree: uint64(math.Pow(2, 15)),
		},
		SymParams: symPasta.Pasta4Param3215,
	},
	{
		Params: Parameter{
			UseBsGs:   true,
			bSgSN1:    8,
			bSgSN2:    4,
			logN:      16,
			plainMod:  1096486890805657601,
			modDegree: uint64(math.Pow(2, 16)),
		},
		SymParams: symPasta.Pasta4Param6015,
	},
}
