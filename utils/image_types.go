package utils

type ImageUint64Vec struct {
	R []uint64
	G []uint64
	B []uint64
}

type ImageFloat64Vec struct {
	R []float64
	G []float64
	B []float64
}

type ImageUint64Mat struct {
	R [][]uint64
	G [][]uint64
	B [][]uint64
}

type ImageFloat64Mat struct {
	R [][]float64
	G [][]float64
	B [][]float64
}

func NewImg64Mat(data ImageUint64Vec, rows, cols int) ImageUint64Mat {
	if len(data.R) != rows*cols {
		panic("data length does not match specified dimensions")
	}

	r := CreateMatrix(rows, cols)
	g := CreateMatrix(rows, cols)
	b := CreateMatrix(rows, cols)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			r[i][j] = data.R[i*cols+j]
			g[i][j] = data.G[i*cols+j]
			b[i][j] = data.B[i*cols+j]
		}
	}

	return ImageUint64Mat{R: r, G: g, B: b}
}

func VecToInterfaceMat[T uint64 | float64](vec []T) [][]interface{} {
	mat := [][]interface{}{make([]interface{}, len(vec))}
	for i, v := range vec {
		mat[0][i] = v
	}
	return mat
}

func MatrixToInterfaceMat[T uint64 | float64](mat [][]T) [][]interface{} {
	newMat := make([][]interface{}, len(mat))
	for i, row := range mat {
		newMat[i] = make([]interface{}, len(row))
		for j, v := range row {
			newMat[i][j] = v
		}
	}
	return newMat
}
