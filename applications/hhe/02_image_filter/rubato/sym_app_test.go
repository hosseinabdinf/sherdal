package rubato

import (
	"sherdal/hhe/sym/rubato"
	"sherdal/utils"
	"testing"
)

func TestApp(t *testing.T) {
	var imageName = "dog_01.jpg"
	// you can re-scale image to get the result faster
	scaledImgName := utils.ReSizeImage(imageName, 5)
	imgBounds, img, _ := utils.GetRGBImage(scaledImgName)

	// select the symmetric parameter set
	params := rubato.Rubato5Param2616

	t.Run("Test Symmetric Rubato: Image Encryption", func(t *testing.T) {
		Run(params, imgBounds, img)
	})
}
