package pasta

import (
	"sherdal/hhe/sym/pasta"
	"sherdal/utils"
	"testing"
)

func TestApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	imgBounds, img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	params := pasta.Pasta3Param1614

	t.Run("Test Symmetric Pasta: Image Encryption", func(t *testing.T) {
		Run(params, imgBounds, img)
	})
}
