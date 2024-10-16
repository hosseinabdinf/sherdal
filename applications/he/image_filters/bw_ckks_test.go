package applications

import (
	"fmt"
	"sherdal/utils"
	"testing"
)

func TestBWFilterCKKS(t *testing.T) {
	for _, tc := range TestVector {
		fmt.Printf("\n ---*** BW Filter CKKS Test #%d, logN=%d, img:%s ***--- \n", tc.t, tc.paramsLiteral.LogN, tc.imageName)
		testBWFilterCKKS(t, tc)
	}
}

func testBWFilterCKKS(t *testing.T, tc TestContext) {
	reScaledImgName := utils.ReSizeImage(tc.imageName, 2)
	t.Run("BWFilter using CKKS scheme", func(t *testing.T) {
		BWFilterCKKS(reScaledImgName, tc.paramsLiteral, true)
	})
}
