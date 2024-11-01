package linear_regression

import (
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"sherdal/configs"
)

type TestCase int

const (
	S TestCase = iota
	M
	L
	XL
	XXL
)

type CkksTestContext struct {
	t             TestCase
	paramsLiteral ckks.ParametersLiteral
}

type BgvTestContext struct {
	t             TestCase
	paramsLiteral bgv.ParametersLiteral
}

type BfvTestContext struct {
	t             TestCase
	paramsLiteral bgv.ParametersLiteral
}

var CKKSTestVector = []CkksTestContext{
	{
		t:             S,
		paramsLiteral: configs.CKKSRealParamsN12QP109,
	},
	{
		t:             M,
		paramsLiteral: configs.CKKSRealParamsN13QP218,
	},
	{
		t:             L,
		paramsLiteral: configs.CKKSRealParamsN14QP438,
	},
	{
		t:             XL,
		paramsLiteral: configs.CKKSRealParamsN15QP881,
	},
	{
		t:             XXL,
		paramsLiteral: configs.CKKSRealParamsPN16QP1761,
	},
}

var BGVTestVector = []BgvTestContext{
	{
		t:             S,
		paramsLiteral: configs.BGVParamsN12QP109,
	},
	{
		t:             M,
		paramsLiteral: configs.BGVParamsN13QP218,
	},
	{
		t:             L,
		paramsLiteral: configs.BGVParamsN14QP438,
	},
	{
		t:             XL,
		paramsLiteral: configs.BGVParamsN15QP880,
	},
}

var BFVTestVector = []BfvTestContext{
	{
		t:             S,
		paramsLiteral: configs.BGVScaleInvariantParamsN12QP109,
	},
	{
		t:             M,
		paramsLiteral: configs.BGVScaleInvariantParamsN13QP218,
	},
	{
		t:             L,
		paramsLiteral: configs.BGVScaleInvariantParamsN14QP438,
	},
	{
		t:             XL,
		paramsLiteral: configs.BGVScaleInvariantParamsN15QP880,
	},
}
