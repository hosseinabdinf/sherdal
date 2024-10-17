package utils

import (
	"github.com/anthonynsimon/bild/imgio"
	"image"
	"image/color"
	"path/filepath"
	"sherdal/applications"
	"sherdal/configs"
	"testing"
)

func TestImage(t *testing.T) {
	var err error
	var img image.Image

	prefix := applications.FindRootPath()
	path := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, "dog_04.jpg")

	// get image and its bounds
	img, err = imgio.Open(path)
	HandleError(err)
	imgBounds := img.Bounds()

	// maximum number of pixel RGB color for vector size
	imgSize := imgBounds.Max.X * imgBounds.Max.Y

	rV := make([]uint64, imgSize)
	gV := make([]uint64, imgSize)
	bV := make([]uint64, imgSize)

	i := 0
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			rV[i] = uint64(r >> 8) // Scale down to uint8 range
			gV[i] = uint64(g >> 8) // Scale down to uint8 range
			bV[i] = uint64(b >> 8) // Scale down to uint8 range
			i++
		}
	}

	newImage := image.NewRGBA(imgBounds)
	index := 0
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			newImage.SetRGBA(x, y, color.RGBA{
				R: uint8(rV[index]),
				G: uint8(gV[index]),
				B: uint8(bV[index]),
				A: uint8(255),
			})
			index++
		}
	}

	err = imgio.Save("./test_img.jpg", newImage, imgio.JPEGEncoder(100))
	HandleError(err)
}
