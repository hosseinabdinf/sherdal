package rubato

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/utils"
)

func TestHHEImgEncApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	// params := rubato.Rubato5Param2616

	t.Run("Test Symmetric Rubato: Image Encryption", func(t *testing.T) {
		HHEImgEncApp(img.Bounds, img)
	})
}

func TestRun(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		run()
	})
}
