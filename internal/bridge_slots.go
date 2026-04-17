package internal

import "sherdal/utils"

// PackCoefficientsBitReversed mirrors the _old RtF coefficient placement where
// the first and second halves are written in bit-reversed order.
func PackCoefficientsBitReversed(values []float64, logN int) []float64 {
	packed := make([]float64, 1<<logN)
	half := len(values) / 2
	for i := 0; i < half; i++ {
		j := utils.BitReverse64(uint64(i), uint64(logN-1))
		packed[j] = values[i]
		packed[j+uint64(half)] = values[i+half]
	}
	return packed
}

func PackCoefficientMatrixBitReversed(data [][]float64, logN int) [][]float64 {
	packed := make([][]float64, len(data))
	for i := range data {
		packed[i] = PackCoefficientsBitReversed(data[i], logN)
	}
	return packed
}

// PackDataToCoefficients mirrors the _old DataToCoefficients helper. The output
// always has length 2^logNOverall, while only the first size values are packed.
func PackDataToCoefficients(values []float64, logNOverall, size int) []float64 {
	packed := make([]float64, 1<<logNOverall)
	half := size / 2
	for i := 0; i < half; i++ {
		j := utils.BitReverse64(uint64(i), uint64(logNOverall-1))
		packed[j] = values[i]
		packed[j+uint64(half)] = values[i+half]
	}
	return packed
}

func PackUintDataToCoefficients(values []uint64, logNOverall, size int) []uint64 {
	packed := make([]uint64, 1<<logNOverall)
	half := size / 2
	for i := 0; i < half; i++ {
		j := utils.BitReverse64(uint64(i), uint64(logNOverall-1))
		packed[j] = values[i]
		packed[j+uint64(half)] = values[i+half]
	}
	return packed
}

// PackKeystreamComponent matches the _old EncodeEncrypt keystream insertion.
func PackKeystreamComponent(values []uint64, logNOverall int) []uint64 {
	packed := make([]uint64, 1<<logNOverall)
	for i, value := range values {
		j := utils.BitReverse64(uint64(i), uint64(logNOverall))
		packed[j] = value
	}
	return packed
}
