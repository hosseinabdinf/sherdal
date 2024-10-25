package utils

import (
	"github.com/anthonynsimon/bild/imgio"
	"github.com/anthonynsimon/bild/transform"
	"image"
	"image/color"
	"math"
	"path/filepath"
	"sherdal/applications"
	"sherdal/configs"
)

// GetRGBImage read the image, and store RGB vectors as
// the ImageUint64Vec and ImageFloat64Vec structures for further process
func GetRGBImage(imageName string) (ImageUint64Vec, ImageFloat64Vec) {
	// read image bounds and RGB vectors
	var err error
	var img image.Image

	prefix := applications.FindRootPath()
	path := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, imageName)

	// get image and its bounds
	img, err = imgio.Open(path)
	HandleError(err)
	imgBounds := img.Bounds()

	// maximum number of pixel RGB color for vector size
	imgSize := imgBounds.Max.X * imgBounds.Max.Y

	i64Red := make([]uint64, imgSize)
	i64Green := make([]uint64, imgSize)
	i64Blue := make([]uint64, imgSize)

	f64Red := make([]float64, imgSize)
	f64Green := make([]float64, imgSize)
	f64Blue := make([]float64, imgSize)

	i := 0
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			// integer values for bgv/bfv
			i64Red[i] = uint64(r >> 8)
			i64Green[i] = uint64(g >> 8)
			i64Blue[i] = uint64(b >> 8)
			// float values for ckks
			f64Red[i] = float64(r)
			f64Green[i] = float64(g)
			f64Blue[i] = float64(b)
			i++
		}
	}

	return ImageUint64Vec{Bounds: imgBounds, R: i64Red, G: i64Green, B: i64Blue}, ImageFloat64Vec{Bounds: imgBounds, R: f64Red, G: f64Green, B: f64Blue}
}

// Pack image R,G,B vectors into one []uint64
func (img *ImageUint64Vec) Pack() (res []uint64) {
	res = make([]uint64, 0, 3*len(img.R))
	res = append(res, img.R...)
	res = append(res, img.G...)
	res = append(res, img.B...)
	return res
}

// UnPack data into image vector R,G,B
func (img *ImageUint64Vec) UnPack(data []uint64) {
	l := len(data) / 3
	img.R = data[:l]
	img.G = data[l:(2 * l)]
	img.B = data[(2 * l):]
	return
}

// Pack image R,G,B vectors into one []float64
func (img *ImageFloat64Vec) Pack() (res []float64) {
	res = make([]float64, 0, 3*len(img.R))
	res = append(res, img.R...)
	res = append(res, img.G...)
	res = append(res, img.B...)
	return res
}

// UnPack data into image vector R,G,B
func (img *ImageFloat64Vec) UnPack(data []float64) {
	l := len(data) / 3
	img.R = data[:l]
	img.G = data[l:(2 * l)]
	img.B = data[(2 * l):]
	return
}

// PreProcessImage converts ImageFloat64Vec data to ImageFloat64Mat
// with respect to numBlock, where numBlock = len(data_vector) / max_slot
func (img *ImageFloat64Vec) PreProcessImage(maxSlot int) (int, ImageFloat64Mat) {
	l := NewLogger(DEBUG)

	// maximum number of pixel RGB color for vector size
	imgSize := len(img.R)

	l.PrintFormatted("Img Bounds: %v, len(rgb): [%d, %d, %d]", img.Bounds, imgSize, imgSize, imgSize)
	if maxSlot < imgSize {
		l.PrintFormatted("Input = %d vs. Max slot = %d ", imgSize, maxSlot)
	}

	numBlock := int(math.Ceil(float64(imgSize) / float64(maxSlot)))
	l.PrintFormatted("Number of blocks: %d ", numBlock)

	// Preprocess image pixels into matrix[num_block][max_slots]
	// float values for ckks
	f64RMat := CreateMatrixFloat(numBlock, maxSlot)
	f64GMat := CreateMatrixFloat(numBlock, maxSlot)
	f64BMat := CreateMatrixFloat(numBlock, maxSlot)

	for i := 0; i < numBlock; i++ {
		for j := 0; j < maxSlot; j++ {
			index := i*maxSlot + j
			if index >= imgSize {
				f64RMat[i][j], f64GMat[i][j], f64BMat[i][j] = 0, 0, 0
			} else {
				f64RMat[i][j] = img.R[index]
				f64GMat[i][j] = img.G[index]
				f64BMat[i][j] = img.B[index]
			}
		}
	}

	return numBlock, ImageFloat64Mat{f64RMat, f64GMat, f64BMat}
}

// PreProcessImage converts ImageUint64Vec data to ImageUint64Mat
// with respect to numBlock, where numBlock = len(data_vector) / max_slot
func (img *ImageUint64Vec) PreProcessImage(maxSlot int) (int, ImageUint64Mat) {
	l := NewLogger(DEBUG)

	// maximum number of pixel RGB color for vector size
	imgSize := len(img.R)

	l.PrintFormatted("Img Bounds: %v, len(rgb): [%d, %d, %d]", img.Bounds, imgSize, imgSize, imgSize)
	if maxSlot < imgSize {
		l.PrintFormatted("Input = %d vs. Max slot = %d ", imgSize, maxSlot)
	}

	numBlock := int(math.Ceil(float64(imgSize) / float64(maxSlot)))
	l.PrintFormatted("Number of blocks: %d ", numBlock)

	// Preprocess image pixels into matrix[num_block][max_slots]
	// integer values for bgv/bfv
	i64RMat := CreateMatrix(numBlock, maxSlot)
	i64GMat := CreateMatrix(numBlock, maxSlot)
	i64BMat := CreateMatrix(numBlock, maxSlot)

	for i := 0; i < numBlock; i++ {
		for j := 0; j < maxSlot; j++ {
			index := i*maxSlot + j
			if index >= imgSize {
				i64RMat[i][j], i64GMat[i][j], i64BMat[i][j] = 0, 0, 0
			} else {
				i64RMat[i][j] = img.R[index]
				i64GMat[i][j] = img.G[index]
				i64BMat[i][j] = img.B[index]
			}
		}
	}

	return numBlock, ImageUint64Mat{i64RMat, i64GMat, i64BMat}
}

// PostProcessBWImage convert the decrypted results of bw filter back into the image
// with corresponding size and save it as a file
func PostProcessBWImage[T uint64 | float64](imageName string, numBlock int, imgBounds image.Rectangle, maxSlot int, identifier string, results [][]T) {
	var err error

	imgSize := imgBounds.Max.X * imgBounds.Max.Y

	grayVec := make([]uint8, imgSize)
	for i := 0; i < numBlock; i++ {
		for j := 0; j < maxSlot; j++ {
			if i*maxSlot+j >= imgSize {
				// we don't use the padding elements
				break
			}
			grayVec[i*maxSlot+j] = uint8(results[i][j])
		}
	}

	grayImage := image.NewGray(imgBounds)
	index := 0
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			grayImage.Set(x, y, color.Gray{Y: grayVec[index]})
			index++
		}
	}

	name := "./outputs/CKKS_" + identifier + "_" + imageName
	err = imgio.Save(name, grayImage, imgio.JPEGEncoder(100))
	HandleError(err)
}

// PostProcessUintImage convert the decrypted results back into the image
// with corresponding size and save it as a file
func PostProcessUintImage(identifier, imageName string, rows, cols int, imgBounds image.Rectangle, results ImageUint64Mat) {
	var err error
	imgSize := imgBounds.Max.X * imgBounds.Max.Y

	rVec := make([]uint8, imgSize)
	gVec := make([]uint8, imgSize)
	bVec := make([]uint8, imgSize)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			vecIndex := i*cols + j
			if vecIndex >= imgSize {
				// we don't use the padding elements
				break
			}
			rVec[vecIndex] = uint8(results.R[i][j])
			gVec[vecIndex] = uint8(results.G[i][j])
			bVec[vecIndex] = uint8(results.B[i][j])
		}
	}

	img := image.NewRGBA(imgBounds)
	index := 0
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			img.Set(x, y, color.RGBA{
				R: rVec[index],
				G: gVec[index],
				B: bVec[index],
				A: uint8(255),
			})
			index++
		}
	}

	name := "./" + identifier + "_" + imageName
	err = imgio.Save(name, img, imgio.JPEGEncoder(100))
	HandleError(err)
}

// ReSizeImage resize image to the respected scale factor
func ReSizeImage(imageName string, scale int) string {
	var err error
	var img image.Image
	prefix := applications.FindRootPath()
	path := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, imageName)

	img, err = imgio.Open(path)
	HandleError(err)

	imgBounds := img.Bounds()
	currentX := imgBounds.Max.X
	currentY := imgBounds.Max.Y

	scaledX := int(math.Round(float64(currentX / scale)))
	scaledY := int(math.Round(float64(currentY / scale)))

	resizedImg := transform.Resize(img, scaledX, scaledY, transform.Linear)
	scaledImgName := "scaled_" + imageName
	newPath := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, scaledImgName)
	err = imgio.Save(newPath, resizedImg, imgio.JPEGEncoder(100))
	HandleError(err)
	return scaledImgName
}

// clampToUint8 clamp values between 0-255
func clampToUint8(value interface{}) uint8 {
	var val float64

	switch v := value.(type) {
	case float64:
		val = v * 255 // Scale if value is in [0, 1]
	case uint64:
		val = float64(v) // Assuming it's already in [0, 255]
	default:
		return 0 // Fallback for unsupported types
	}

	if val < 0 {
		return 0
	} else if val > 255 {
		return 255
	}
	return uint8(val)
}
