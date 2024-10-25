package applications

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
	imageName     string
	paramsLiteral ckks.ParametersLiteral
}

type BgvTestContext struct {
	t             TestCase
	imageName     string
	paramsLiteral bgv.ParametersLiteral
}

type BfvTestContext struct {
	t             TestCase
	imageName     string
	paramsLiteral bgv.ParametersLiteral
}

var ImageName = "dog_04.jpg"

var CKKSTestVector = []CkksTestContext{
	{
		t:             S,
		imageName:     ImageName,
		paramsLiteral: configs.CKKSRealParamsN12QP109,
	},
	{
		t:             M,
		imageName:     ImageName,
		paramsLiteral: configs.CKKSRealParamsN13QP218,
	},
	{
		t:             L,
		imageName:     ImageName,
		paramsLiteral: configs.CKKSRealParamsN14QP438,
	},
	{
		t:             XL,
		imageName:     ImageName,
		paramsLiteral: configs.CKKSRealParamsN15QP881,
	},
	{
		t:             XXL,
		imageName:     ImageName,
		paramsLiteral: configs.CKKSRealParamsPN16QP1761,
	},
}

var BGVTestVector = []BgvTestContext{
	{
		t:             S,
		imageName:     ImageName,
		paramsLiteral: configs.BGVParamsN12QP109,
	},
	{
		t:             M,
		imageName:     ImageName,
		paramsLiteral: configs.BGVParamsN13QP218,
	},
	{
		t:             L,
		imageName:     ImageName,
		paramsLiteral: configs.BGVParamsN14QP438,
	},
	{
		t:             XL,
		imageName:     ImageName,
		paramsLiteral: configs.BGVParamsN15QP880,
	},
}

var BFVTestVector = []BfvTestContext{
	{
		t:             S,
		imageName:     ImageName,
		paramsLiteral: configs.BGVScaleInvariantParamsN12QP109,
	},
	{
		t:             M,
		imageName:     ImageName,
		paramsLiteral: configs.BGVScaleInvariantParamsN13QP218,
	},
	{
		t:             L,
		imageName:     ImageName,
		paramsLiteral: configs.BGVScaleInvariantParamsN14QP438,
	},
	{
		t:             XL,
		imageName:     ImageName,
		paramsLiteral: configs.BGVScaleInvariantParamsN15QP880,
	},
}
