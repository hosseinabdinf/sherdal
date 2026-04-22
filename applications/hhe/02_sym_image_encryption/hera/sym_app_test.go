package hera

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/ske/hera"
	"github.com/hosseinabdinf/sherdal/utils"
)

func TestApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	params := hera.Hera4Params2816

	t.Run("Test Symmetric Hera: Image Encryption", func(t *testing.T) {
		ImgEncApp(params, img.Bounds, img)
	})
}
