package utils

import (
	"github.com/anthonynsimon/bild/imgio"
	"github.com/anthonynsimon/bild/transform"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"os"
	"path/filepath"
	"sherdal/applications"
	"sherdal/configs"
)

// OpenJpegImage read the image file from the path and returns it
func OpenJpegImage(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	img, err := jpeg.Decode(file)
	if err != nil {
		return nil, err
	}

	return img, nil
}

// SaveJpegImage saves the image as a file into the path
func SaveJpegImage(filePath string, img image.Image) error {
	outFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	err = jpeg.Encode(outFile, img, nil)
	if err != nil {
		return err
	}

	return nil
}

// ImageData take care of accessing different types int64, float64 when
// working with both integer based and floating point based schemes
type ImageData interface {
	GetR() [][]uint64
	GetG() [][]uint64
	GetB() [][]uint64
}

// ImageInt64 define uint64 structure for image data
type ImageInt64 struct {
	R [][]uint64
	G [][]uint64
	B [][]uint64
}

func (img ImageInt64) GetR() [][]uint64 { return img.R }
func (img ImageInt64) GetG() [][]uint64 { return img.G }
func (img ImageInt64) GetB() [][]uint64 { return img.B }

// ImageFloat64 define float64 structure for image data
type ImageFloat64 struct {
	R [][]float64
	G [][]float64
	B [][]float64
}

func (img ImageFloat64) GetR() [][]uint64 {
	r := make([][]uint64, len(img.R))
	for i := range img.R {
		r[i] = make([]uint64, len(img.R[i]))
		for j := range img.R[i] {
			r[i][j] = uint64(img.R[i][j])
		}
	}
	return r
}

func (img ImageFloat64) GetG() [][]uint64 {
	g := make([][]uint64, len(img.G))
	for i := range img.G {
		g[i] = make([]uint64, len(img.G[i]))
		for j := range img.G[i] {
			g[i][j] = uint64(img.G[i][j])
		}
	}
	return g
}

func (img ImageFloat64) GetB() [][]uint64 {
	b := make([][]uint64, len(img.B))
	for i := range img.B {
		b[i] = make([]uint64, len(img.B[i]))
		for j := range img.B[i] {
			b[i][j] = uint64(img.B[i][j])
		}
	}
	return b
}

// PreProcessImage read the image, and convert RGB vectors of data to
// Int64 and Float64 structures with respect to the number of
// block, where number of block = len_data_vector / max_slot
func PreProcessImage(imageName string, maxSlot int) (numBlock int, imgBounds image.Rectangle, imageInt64 ImageInt64, imageFloat64 ImageFloat64) {
	// read image bounds and RGB vectors
	var err error
	var img image.Image
	l := NewLogger(DEBUG)

	prefix := applications.FindRootPath()
	path := filepath.Join(prefix, configs.DatasetDir, configs.DogsDir, imageName)

	// get image and its bounds
	img, err = OpenJpegImage(path)
	HandleError(err)
	imgBounds = img.Bounds()

	// maximum number of pixel RGB color for vector size
	vecSize := imgBounds.Max.X * imgBounds.Max.Y

	i64RedVec := make([]uint64, vecSize)
	i64GreenVec := make([]uint64, vecSize)
	i64BlueVec := make([]uint64, vecSize)

	f64RedVec := make([]float64, vecSize)
	f64GreenVec := make([]float64, vecSize)
	f64BlueVec := make([]float64, vecSize)

	i := 0
	// iterate image pixel by pixel
	for y := imgBounds.Min.Y; y < imgBounds.Max.Y; y++ {
		for x := imgBounds.Min.X; x < imgBounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			i64RedVec[i] = uint64(r)
			i64GreenVec[i] = uint64(g)
			i64BlueVec[i] = uint64(b)

			f64RedVec[i] = float64(r)
			f64GreenVec[i] = float64(g)
			f64BlueVec[i] = float64(b)

			i++
		}
	}

	l.PrintFormatted("Img Bounds: %v, len(rgb): [%d, %d, %d]", imgBounds, vecSize, vecSize, vecSize)
	if maxSlot < vecSize {
		l.PrintFormatted("Input = %d vs. Max slot = %d ", vecSize, maxSlot)
	}

	numBlock = int(math.Ceil(float64(vecSize) / float64(maxSlot)))
	l.PrintFormatted("Number of blocks: %d ", numBlock)

	// Preprocess image pixels
	i64RVecS := make([][]uint64, numBlock)
	i64GVecS := make([][]uint64, numBlock)
	i64BVecS := make([][]uint64, numBlock)
	f64RVecS := make([][]float64, numBlock)
	f64GVecS := make([][]float64, numBlock)
	f64BVecS := make([][]float64, numBlock)
	for i := 0; i < numBlock; i++ {
		i64RVecS[i] = make([]uint64, maxSlot)
		i64GVecS[i] = make([]uint64, maxSlot)
		i64BVecS[i] = make([]uint64, maxSlot)
		f64RVecS[i] = make([]float64, maxSlot)
		f64GVecS[i] = make([]float64, maxSlot)
		f64BVecS[i] = make([]float64, maxSlot)
		for j := 0; j < maxSlot; j++ {
			if i*maxSlot+j >= vecSize {
				i64RVecS[i][j] = 0
				i64GVecS[i][j] = 0
				i64BVecS[i][j] = 0
				f64RVecS[i][j] = 0
				f64GVecS[i][j] = 0
				f64BVecS[i][j] = 0
			} else {
				i64RVecS[i][j] = i64RedVec[(i*maxSlot)+j]
				i64GVecS[i][j] = i64GreenVec[(i*maxSlot)+j]
				i64BVecS[i][j] = i64BlueVec[(i*maxSlot)+j]
				f64RVecS[i][j] = f64RedVec[(i*maxSlot)+j]
				f64GVecS[i][j] = f64GreenVec[(i*maxSlot)+j]
				f64BVecS[i][j] = f64BlueVec[(i*maxSlot)+j]
			}
		}
	}
	imageInt64 = ImageInt64{i64RVecS, i64GVecS, i64BVecS}
	imageFloat64 = ImageFloat64{f64RVecS, f64GVecS, f64BVecS}
	return
}

// PostProcessBWImage convert the decrypted results of bw filter back into the image
// with corresponding size and save it as a file
func PostProcessBWImage[T uint64 | float64](imageName string, numBlock int, imgBounds image.Rectangle, maxSlot int, identifier string, results [][]T) {
	var err error

	vecSize := imgBounds.Max.X * imgBounds.Max.Y

	grayVec := make([]uint8, vecSize)
	for i := 0; i < numBlock; i++ {
		for j := 0; j < maxSlot; j++ {
			if i*maxSlot+j >= vecSize {
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

	err = SaveJpegImage("./outputs/CKKS_"+identifier+"_"+imageName, grayImage)
	HandleError(err)
}

// PostProcessImage convert the decrypted results back into the image
// with corresponding size and save it as a file
func PostProcessImage[T ImageData](imageName string, numBlock int, imgBounds image.Rectangle, maxSlot int, identifier string, results T) {
	var err error
	vecSize := imgBounds.Max.X * imgBounds.Max.Y

	rVec := make([]uint8, vecSize)
	gVec := make([]uint8, vecSize)
	bVec := make([]uint8, vecSize)
	for i := 0; i < numBlock; i++ {
		for j := 0; j < maxSlot; j++ {
			if i*maxSlot+j >= vecSize {
				// we don't use the padding elements
				break
			}
			rVec[i*maxSlot+j] = uint8(results.GetR()[i][j])
			gVec[i*maxSlot+j] = uint8(results.GetG()[i][j])
			bVec[i*maxSlot+j] = uint8(results.GetB()[i][j])
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

	err = SaveJpegImage("./"+identifier+"_"+imageName, img)
	HandleError(err)
}

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
	err = SaveJpegImage(newPath, resizedImg)
	HandleError(err)
	return scaledImgName
}
