package hera

import (
	"sherdal/hhe/sym/hera"
	"sherdal/utils"
	"testing"
)

func TestApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	imgBounds, img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	params := hera.Hera4Params2816

	t.Run("Test Symmetric Hera: Image Encryption", func(t *testing.T) {
		Run(params, imgBounds, img)
	})
}
