package sym

type Key []uint64
type Block []uint64
type Vector3D [][][]uint64
type Plaintext []uint64
type Ciphertext []uint64
type Matrix [][]uint64
type SBox []uint64

//func ConvertPtVecToInterfaceMat[T Plaintext](pt []T) [][]interface{} {
//	result := make([][]interface{}, len(pt))
//	for i := range pt {
//		result[i] = make([]interface{}, len(pt[i]))
//		for j := range pt[i] {
//			result[i][j] = pt[i][j]
//		}
//	}
//	return result
//}
//
//func ConvertPtVecToUint64Mat[T Plaintext](pt []T) [][]uint64 {
//	result := make([][]uint64, len(pt))
//	for i := range pt {
//		result[i] = make([]uint64, len(pt[i]))
//		for j := range pt[i] {
//			result[i][j] = uint64(pt[i][j])
//		}
//	}
//	return result
//}

//func ConvertPtToUint64Mat[T Plaintext](pt T) [][]uint64 {
//	result := make([][]uint64, 1)
//	result[0] = make([]uint64, len(pt))
//	for i := range pt {
//		result[0][i] = pt[i]
//	}
//	return result
//}

func MatrixToInterfaceMat(mat Matrix) [][]interface{} {
	result := make([][]interface{}, len(mat))
	for i := range mat {
		result[i] = make([]interface{}, len(mat[i]))
		for j := range mat[i] {
			result[i][j] = mat[i][j]
		}
	}
	return result
}
