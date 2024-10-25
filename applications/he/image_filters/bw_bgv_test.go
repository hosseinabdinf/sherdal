package applications

import (
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"sherdal/utils"
	"testing"
)

func TestBWFilterBGV(t *testing.T) {
	for _, tc := range BGVTestVector {
		//fmt.Printf("\n ---*** BW Filter CKKS Test #%d, logN=%d, img:%s ***--- \n", tc.t, tc.paramsLiteral.LogN, tc.imageName)
		testBWFilterBGV(t, tc)
	}
}

func testBWFilterBGV(t *testing.T, tc BgvTestContext) {
	var bw BwBGV
	var err error
	// initiate the params
	params, err := bgv.NewParametersFromLiteral(tc.paramsLiteral)
	utils.HandleError(err)

	publicParams, err := params.MarshalJSON()
	utils.HandleError(err)

	reScaleImgName := utils.ReSizeImage(tc.imageName, 2)
	img, _ := utils.GetRGBImage(reScaleImgName)
	data := img.Pack()

	t.Run("BWFilter using BGV scheme", func(t *testing.T) {

		pk, evk, ciphers := bw.Client(publicParams, data)

		bw.Server(publicParams, pk, evk, ciphers)
	})

}
