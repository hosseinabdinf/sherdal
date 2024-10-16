package pasta

type TestCase int

type TestContext struct {
	Params Parameter
}

// Decryption Test Vectors
var pasta3TestVector = []TestContext{
	{
		Params: Pasta3Param1614,
	}, {
		Params: Pasta3Param3215,
	}, {
		Params: Pasta3Param6015,
	},
}

var pasta4TestVector = []TestContext{
	{
		Params: Pasta4Param1614,
	}, {
		Params: Pasta4Param3215,
	}, {
		Params: Pasta4Param6015,
	},
}
