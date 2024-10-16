package utils

import (
	"encoding/csv"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"os"
	"sherdal/hhe/sym"
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

func printSummarized2DArray(arr [][]float64, numRows int, numElements int) {
	const summaryLength = 5 // Number of elements to show at the start and end of each row

	for i := 0; i < numRows; i++ {
		fmt.Printf("Row %d:\n", i)
		if numElements > 2*summaryLength {
			// Print first few elements
			for j := 0; j < summaryLength; j++ {
				fmt.Printf("%.2f ", arr[i][j])
			}
			fmt.Printf("... ")
			// Print last few elements
			for j := numElements - summaryLength; j < numElements; j++ {
				fmt.Printf("%.2f ", arr[i][j])
			}
		} else {
			// If the row is shorter than the summary length, print all elements
			for j := 0; j < numElements; j++ {
				fmt.Printf("%.2f ", arr[i][j])
			}
		}
		fmt.Println()
	}
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

// Uint64ToHex converts a vector of uint64 elements to hexadecimal values
// and print them
func Uint64ToHex(data []uint64) {
	hexData := make([]string, len(data))
	for i, v := range data {
		hexData[i] = fmt.Sprintf("%#x", v)
	}
	fmt.Println(hexData)
}

func ConvertToInterfaceSlice[T uint64 | float64](mat [][]T) [][]interface{} {
	result := make([][]interface{}, len(mat))
	for i := range mat {
		result[i] = make([]interface{}, len(mat[i]))
		for j := range mat[i] {
			result[i][j] = mat[i][j]
		}
	}
	return result
}

func ConvertPToInterfaceSlice[T sym.Plaintext](mat []T) [][]interface{} {
	result := make([][]interface{}, len(mat))
	for i := range mat {
		result[i] = make([]interface{}, len(mat[i]))
		for j := range mat[i] {
			result[i][j] = mat[i][j]
		}
	}
	return result
}

func ConvertPtxToUi64Slice[T sym.Plaintext](pt []T) [][]uint64 {
	result := make([][]uint64, len(pt))
	for i := range pt {
		result[i] = make([]uint64, len(pt[i]))
		for j := range pt[i] {
			result[i][j] = uint64(pt[i][j])
		}
	}
	return result
}

func ConvertMatToInterfaceMat(mat sym.Matrix) [][]interface{} {
	result := make([][]interface{}, len(mat))
	for i := range mat {
		result[i] = make([]interface{}, len(mat[i]))
		for j := range mat[i] {
			result[i][j] = mat[i][j]
		}
	}
	return result
}
