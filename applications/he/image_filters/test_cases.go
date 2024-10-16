package applications

import (
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

type TestContext struct {
	t             TestCase
	imageName     string
	paramsLiteral ckks.ParametersLiteral
}

var ImageName = "dog_04.jpg"

var TestVector = []TestContext{
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
