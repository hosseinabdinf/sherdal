package utils

import (
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"math"
	"os"
	"sherdal/hhe/sym"
	"strings"
)

// HandleError checks the error and throws a fatal log if the error isn't nil
func HandleError(err error) {
	if err != nil {
		fmt.Printf("|-> Error: %s\n", err.Error())
		panic("=== Panic\n ")
	}
}

// InitCKKS returns an instance of ckks parameters along with the encoder,
// encryptor, and decryptor initiated by the parameters
func InitCKKS(paramsLiteral ckks.ParametersLiteral) (ckks.Parameters, *ckks.Encoder, *rlwe.Encryptor, *rlwe.Decryptor, *ckks.Evaluator) {
	var err error

	params, err := ckks.NewParametersFromLiteral(paramsLiteral)
	HandleError(err)

	keygen := rlwe.NewKeyGenerator(params)

	sk := keygen.GenSecretKeyNew()

	ecd := ckks.NewEncoder(params)

	enc := ckks.NewEncryptor(params, sk)

	dec := ckks.NewDecryptor(params, sk)

	rlk := keygen.GenRelinearizationKeyNew(sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	eval := ckks.NewEvaluator(params, evk)

	return params, ecd, enc, dec, eval
}

// Size measure a ciphertext size and return the size value in bytes
func Size(cipher rlwe.Ciphertext) (size int) {
	return size
}

// SavePlainToFile save the given Plaintext as hexadecimal values to a file
func SavePlainToFile(name string, p sym.Plaintext) {
	// Open a file for writing
	file, err := os.Create(name + ".txt")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Create a new CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write each element of the slice as a separate row in the CSV file
	for _, val := range p {
		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(name, " saved to file")
}

// SaveCipherToFile save the given Ciphertext as hexadecimal values to a file
func SaveCipherToFile(name string, c sym.Ciphertext) {
	// Open a file for writing
	file, err := os.Create(name + ".txt")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Create a new CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write each element of the slice as a separate row in the CSV file
	for _, val := range c {
		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(name, " saved to file")
}

// SaveToFile save the given Plaintext as hexadecimal values to a file
//func (p sym.Plaintext) SaveToFile(name string) {
//	// Open a file for writing
//	file, err := os.Create(name + ".txt")
//	if err != nil {
//		panic(err)
//	}
//	defer func(file *os.File) {
//		err := file.Close()
//		if err != nil {
//			panic(err)
//		}
//	}(file)
//
//	// Create a new CSV writer
//	writer := csv.NewWriter(file)
//	defer writer.Flush()
//
//	// Write each element of the slice as a separate row in the CSV file
//	for _, val := range p {
//		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
//		if err != nil {
//			panic(err)
//		}
//	}
//	fmt.Println(name, " saved to file")
//}

// SaveToFile save the given Ciphertext as hexadecimal values to a file
//func (c Ciphertext) SaveToFile(name string) {
//	// Open a file for writing
//	file, err := os.Create(name + ".txt")
//	if err != nil {
//		panic(err)
//	}
//	defer func(file *os.File) {
//		err := file.Close()
//		if err != nil {
//			panic(err)
//		}
//	}(file)
//
//	// Create a new CSV writer
//	writer := csv.NewWriter(file)
//	defer writer.Flush()
//
//	// Write each element of the slice as a separate row in the CSV file
//	for _, val := range c {
//		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
//		if err != nil {
//			panic(err)
//		}
//	}
//	fmt.Println(name, " saved to file")
//}

// Uint64ToHex converts a vector of uint64 elements to hexadecimal values
// and print them
func Uint64ToHex(data []uint64) {
	hexData := make([]string, len(data))
	for i, v := range data {
		hexData[i] = fmt.Sprintf("%#x", v)
	}
	fmt.Println(hexData)
}

// ScaleUp scale up the f by p
// and return the integer value
func ScaleUp(f float64, scaleFactor float64) uint64 {
	return uint64(math.Round(f * scaleFactor))
}

// ScaleDown scale an integer value x by p
// and return the floating point value
func ScaleDown(x uint64, scaleFactor float64) float64 {
	return float64(x) / scaleFactor
}

// TestVectorGen to generate random values for test vectors
func TestVectorGen(n int, modulus uint64) {
	nonces := make([][]byte, n)
	for i := 0; i < n; i++ {
		nonces[i] = make([]byte, 8)
		_, err := rand.Read(nonces[i])
		if err != nil {
			panic(err)
		}
	}
	fmt.Print("{")
	for i := 0; i < n; i++ {
		result := bytesToHexWithModulus(nonces[i], modulus)
		fmt.Printf("%s, ", result)
		if (i+1)%4 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Print("}\n")
}

func bytesToHexWithModulus(data []byte, modulus uint64) string {
	// Convert bytes to uint64 and take modulus
	result := make([]uint64, len(data)/8)
	for i := 0; i < len(data)/8; i++ {
		result[i] = uint64(data[i*8]) |
			uint64(data[i*8+1])<<8 |
			uint64(data[i*8+2])<<16 |
			uint64(data[i*8+3])<<24 |
			uint64(data[i*8+4])<<32 |
			uint64(data[i*8+5])<<40 |
			uint64(data[i*8+6])<<48 |
			uint64(data[i*8+7])<<56

		result[i] %= modulus
	}

	// Convert uint64 to hexadecimal string
	hexValues := make([]string, len(result))
	for i, v := range result {
		hexValues[i] = fmt.Sprintf("%#x", v)
	}

	// Join hexadecimal values into a string
	return strings.Join(hexValues, ", ")
}

// RandomFloatDataGen to generate a matrix of floating point numbers between 0 and 1
func RandomFloatDataGen(col int, row int) (data [][]float64) {
	data = make([][]float64, row)
	for s := 0; s < row; s++ {
		data[s] = make([]float64, col)
		for i := 0; i < col; i++ {
			data[s][i] = sampling.RandFloat64(0, 1)
		}
	}
	return
}

// Scale data to save as []uint64
//delta := float64(tc.params.GetModulus()) / float64(N)
//for s := 0; s < optSize; s++ {
//	plaintext := func() []uint64 {
//		result := make([]uint64, len(data[s]))
//		for i, v := range data[s] {
//			result[i] = sym.ScaleUp(v, delta)
//		}
//		return result
//	}()
//	fmt.Println("Len: ", len(plaintext), " - OG: ", data[0])
//	sym.Uint64ToHex(plaintext)
//fmt.Println(">  Encrypt() the data[", s, "]")

// RotateSlice to rotate a slice by a given offset
func RotateSlice(slice sym.Block, offset uint64) {
	l := len(slice)
	if l == 0 {
		return
	}

	// Normalize offset to be within the slice's length
	offset %= uint64(l)
	// Rotate the slice elements
	Reverse(slice[:offset])
	Reverse(slice[offset:])
	Reverse(slice)
}

// Reverse to reverse a slice
func Reverse(slice sym.Block) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// ResizeSlice resize the old slice
func ResizeSlice(oldSlice sym.Block, newLen uint64) (newSlice sym.Block) {
	l := uint64(len(oldSlice))
	if newLen == l {
		newSlice = oldSlice
	} else if newLen > l {
		newSlice = append(oldSlice, make(sym.Block, newLen-l)...)
	} else {
		newSlice = oldSlice[:newLen]
	}
	return
}

// CreateMatrix Helper function to create a matrix for uint64
func CreateMatrix(rows int, cols int) [][]uint64 {
	mat := make([][]uint64, rows)
	for i := range mat {
		mat[i] = make([]uint64, cols)
	}
	return mat
}

// CreateMatrixFloat Helper function to create a matrix for float64
func CreateMatrixFloat(rows int, cols int) [][]float64 {
	mat := make([][]float64, rows)
	for i := range mat {
		mat[i] = make([]float64, cols)
	}
	return mat
}
