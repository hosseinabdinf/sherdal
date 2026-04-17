package aes

import (
	"fmt"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type BitSet struct {
	bits []uint8
	size int
}

func NewBitSet(size int) *BitSet {
	return &BitSet{
		bits: make([]uint8, size),
		size: size,
	}
}

func (b *BitSet) Set(x int) {
	if x < 0 {
		panic("x value must > 0")
	}
	for i := 0; i < b.size; i++ {
		b.bits[i] = uint8(x & 0x1)
		x >>= 1
	}
}

func (b *BitSet) SetBytes(data []byte) {
	if len(data)*8 != b.size {
		panic(fmt.Sprintf("invalid byte length: got %d for bitset size %d", len(data), b.size))
	}

	for i := 0; i < len(data); i++ {
		for j := 0; j < 8; j++ {
			b.bits[i*8+j] = (data[i] >> uint(j)) & 1
		}
	}
}

func (b *BitSet) ToBytes() []byte {
	if b.size%8 != 0 {
		panic("bitset size must be a multiple of 8")
	}

	out := make([]byte, b.size/8)
	for i := 0; i < len(out); i++ {
		var v uint8
		for j := 0; j < 8; j++ {
			v |= b.bits[i*8+j] << uint(j)
		}
		out[i] = v
	}

	return out
}

func (b *BitSet) ToULong() uint64 {
	var Out uint64
	for i, bit := range b.bits {
		Out = Out + uint64(bit<<i)
	}
	return Out
}

func (b *BitSet) ToString() string {
	var sb strings.Builder
	for _, byte := range b.bits {
		if byte == 1 {
			sb.WriteString("1")
		} else {
			sb.WriteString("0")
		}
	}
	return sb.String()
}

func (b *BitSet) Copy() *BitSet {
	out := NewBitSet(b.size)
	for i, bit := range b.bits {
		if bit == 1 {
			out.bits[i] = 1
		} else {
			out.bits[i] = 0
		}
	}
	return out
}

func Xor(v0, v1 *BitSet) *BitSet {

	if v0.size != v1.size {
		panic("bit sets have different sizes")
	}
	Out := NewBitSet(v0.size)
	for i := 0; i < v0.size; i++ {
		Out.bits[i] = v0.bits[i] ^ v1.bits[i]
	}
	return Out
}

func (b *BitSet) GetSize() int {
	return b.size
}

func vectorLeftRotationInplace(vector []*rlwe.Ciphertext, rotNum int) {
	for i := 0; i < rotNum; i++ {
		first := vector[0]
		copy(vector, vector[1:])
		vector[len(vector)-1] = first
	}
}

func vectorRightRotationInplace(vector []*rlwe.Ciphertext, rotNum int) {
	for i := 0; i < rotNum; i++ {
		last := vector[len(vector)-1]
		copy(vector[1:], vector)
		vector[0] = last
	}
}

func ctr(iv *BitSet, ctr uint64) *BitSet {
	if iv.size%8 != 0 {
		panic("bitset size must be a multiple of 8")
	}

	ctrBytes := iv.ToBytes()
	carry := ctr

	for i := len(ctrBytes) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(ctrBytes[i]) + (carry & 0xff)
		ctrBytes[i] = uint8(sum)
		carry = (carry >> 8) + (sum >> 8)
	}

	out := NewBitSet(iv.size)
	out.SetBytes(ctrBytes)
	return out
}

// MinInt returns the minimum value of the input of int values.
func MinInt(a, b int) (r int) {
	if a <= b {
		return a
	}
	return b
}
