package applications

import (
	"fmt"
	"image"
	"path/filepath"
	"sherdal/configs"
	"sherdal/utils"
	"testing"
)

func TestBWFilterVanilla(t *testing.T) {
	for _, tc := range TestVector {
		fmt.Printf("\n *** BW Filter Vanilla Test #%d, img: %s \n", tc.t, tc.imageName)
		testBWFilterVanilla(t, tc.imageName)
	}
}

func testBWFilterVanilla(t *testing.T, imgName string) {
	var err error
	var img, gImg image.Image
	prefix := "../../"

	path := filepath.Join(prefix, configs.DatasetDir, imgName)

	img, err = utils.OpenJpegImage(path)
	utils.HandleError(err)

	t.Run("Vanilla Black and White Filter", func(t *testing.T) {
		gImg, err = BWFilterVanilla(img)
	})

	utils.HandleError(err)

	err = utils.SaveJpegImage("./outputs/Vanilla_"+imgName, gImg)
	utils.HandleError(err)
	fmt.Printf("=== Done!\n")
}
