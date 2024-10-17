package applications

import (
	"fmt"
	"github.com/anthonynsimon/bild/imgio"
	"image"
	"path/filepath"
	"sherdal/applications"
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

	//reScaledImgName := utils.ReSizeImage(imgName, 5)

	prefix := applications.FindRootPath()
	path := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, imgName)

	// get image and its bounds
	img, err = imgio.Open(path)
	utils.HandleError(err)

	t.Run("Vanilla Black and White Filter", func(t *testing.T) {
		gImg, err = BWFilterVanilla(img)
	})

	utils.HandleError(err)
	name := "./outputs/Vanilla_" + imgName
	err = imgio.Save(name, gImg, imgio.JPEGEncoder(100))
	utils.HandleError(err)
	fmt.Printf("=== Done!\n")
}
