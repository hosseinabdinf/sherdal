package applications

import (
	"image"
	"image/color"
)

func BWFilterVanilla(img image.Image) (image.Image, error) {
	bounds := img.Bounds()
	grayImg := image.NewGray(bounds)

	// normalize RGB color values to the range [0, 255]
	normalizeColor := func(c float64) float64 {
		return c / 65535.0 * 255.0
	}

	// iterate image pixel by pixel
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			// Calculate the grayscale value using a 01_sym_encryption average
			grayValue := (normalizeColor(float64(r)) + normalizeColor(float64(g)) + normalizeColor(float64(b))) / 3

			// Convert the grayscale value back to the range [0, 65535] and set the pixel
			grayColor := uint8(grayValue)
			grayImg.Set(x, y, color.Gray{Y: grayColor})
		}
	}

	return grayImg, nil
}
