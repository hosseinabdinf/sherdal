package linear_regression

import (
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"sherdal/utils"
	"testing"
)

func TestLRBgv(t *testing.T) {
	//for _, tc := range BGVTestVector {
	//	testLRBgv(t, tc)
	//}

	testLRBgv(t, BGVTestVector[0])
}

func testLRBgv(t *testing.T, tc BgvTestContext) {
	logger := utils.NewLogger(utils.DEBUG)
	params, err := bgv.NewParametersFromLiteral(tc.paramsLiteral)
	utils.HandleError(err)

	publicParams, err := params.MarshalBinary()
	utils.HandleError(err)

	client := Client{logger: logger}
	_, evk := client.Setup(publicParams)

	data := []uint64{2, 4, 6, 8}
	weights := []uint64{3, 4, 6, 4}
	biases := []uint64{1, 1, 1, 1}

	cData := client.Encrypt(data)
	cWeights := client.Encrypt(weights)
	cBiases := client.Encrypt(biases)

	server := Server{logger: logger}
	server.Setup(publicParams, evk)
	resCipher := server.Evaluate(cData, cWeights, cBiases)

	res := client.Decrypt(resCipher)
	logger.PrintSummarizedVector("Data", data, len(data))
	logger.PrintSummarizedVector("Weights", weights, len(weights))
	logger.PrintSummarizedVector("Biases", biases, len(biases))
	logger.PrintSummarizedVector("Result", res, len(res))
}
