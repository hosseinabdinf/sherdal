package hera

type TestCase int

const (
	HR80F = iota
	HR80S
	HR80AF
	HR80AS
)

const (
	HR128F = iota
	HR128S
	HR128AF
	HR128AS
)

type TestContext struct {
	FVParamIndex int
	Radix        int
	Params       Parameter
}

// TestVector Test Vectors
var TestVector = []TestContext{
	//	HERA 80 bits security
	{
		FVParamIndex: HR80F,
		Radix:        2,
		Params:       Hera4Params2816,
	},
	{
		FVParamIndex: HR80S,
		Radix:        0,
		Params:       Hera4Params2816,
	},
	{
		FVParamIndex: HR80AF,
		Radix:        2,
		Params:       Hera4Params2516,
	},
	{
		FVParamIndex: HR80AS,
		Radix:        0,
		Params:       Hera4Params2516,
	}, //	HERA 128 bits security
	{
		FVParamIndex: HR128F,
		Radix:        2,
		Params:       Hera5Params2816,
	},
	{
		FVParamIndex: HR128S,
		Radix:        0,
		Params:       Hera5Params2816,
	},
	{
		FVParamIndex: HR128AF,
		Radix:        2,
		Params:       Hera5Params2516,
	},
	{
		FVParamIndex: HR128AS,
		Radix:        2,
		Params:       Hera5Params2516,
	},
}
