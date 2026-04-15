package sym

import "encoding/binary"

const (
	NonceSize        = 8
	DefaultNonceSeed = uint64(123456789)
)

func CeilDiv(n, d int) int {
	if d <= 0 {
		panic("division by non-positive value")
	}
	if n <= 0 {
		return 0
	}
	return 1 + (n-1)/d
}

func CloneKey(key Key) Key {
	return append(Key(nil), key...)
}

func CloneBlock(block Block) Block {
	return append(Block(nil), block...)
}

func CloneMatrix(mat Matrix) Matrix {
	clone := make(Matrix, len(mat))
	for i := range mat {
		clone[i] = CloneBlock(mat[i])
	}
	return clone
}

func DefaultNonce() []byte {
	nonce := make([]byte, NonceSize)
	FillNonce(nonce, DefaultNonceSeed, 0)
	return nonce
}

func NormalizeNonce(nonce []byte) []byte {
	if len(nonce) == 0 {
		return DefaultNonce()
	}
	if len(nonce) != NonceSize {
		panic("invalid nonce length")
	}
	return append([]byte(nil), nonce...)
}

func NonceSeed(nonce []byte) uint64 {
	if len(nonce) == 0 {
		return DefaultNonceSeed
	}
	if len(nonce) != NonceSize {
		panic("invalid nonce length")
	}
	return binary.BigEndian.Uint64(nonce)
}

func FillNonce(dst []byte, base uint64, offset int) {
	if len(dst) < NonceSize {
		panic("invalid nonce buffer length")
	}
	binary.BigEndian.PutUint64(dst[:NonceSize], base+uint64(offset))
}
