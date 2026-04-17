package internal

func DeterministicNonces(count, size int) [][]byte {
	nonces := make([][]byte, count)
	for i := 0; i < count; i++ {
		nonces[i] = make([]byte, size)
		for j := 0; j < size; j++ {
			nonces[i][j] = byte(i + j + 1)
		}
	}
	return nonces
}
