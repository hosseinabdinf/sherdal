package rubato

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/ske/rubato"
	"github.com/hosseinabdinf/sherdal/utils"
)

func TestApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	params := rubato.Rubato2Param2516

	t.Run("Test Symmetric Rubato: Image Encryption", func(t *testing.T) {
		ImgEncApp(params, img.Bounds, img)
	})
}
