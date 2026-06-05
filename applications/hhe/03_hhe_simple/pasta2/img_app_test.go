package pasta2

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/utils"
)

func TestHHEImgEncApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	img, _ := utils.GetRGBImage(scaledImgName)

	t.Run("Test Symmetric Pasta2: Image Encryption", func(t *testing.T) {
		HHEImgEncApp(img.Bounds, img)
	})
}

func TestRun(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		run()
	})
}
