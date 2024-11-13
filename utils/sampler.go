package utils

import (
	"io"
	"math/bits"
)

// SampleZqx returns uniform random value in (0,q) by rejection sampling
func SampleZqx(rand io.Reader, q uint64) (res uint64) {
	bitLen := bits.Len64(q - 2)
	byteLen := (bitLen + 7) / 8
	b := bitLen % 8
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, byteLen)
	for {
		_, err := io.ReadFull(rand, bytes)
		if err != nil {
			panic(err)
		}
		bytes[byteLen-1] &= uint8((1 << b) - 1)

		res = 0
		for i := 0; i < byteLen; i++ {
			res += uint64(bytes[i]) << (8 * i)
		}

		if res < q {
			return
		}
	}
}

// SampleZq returns a uniform random value in (0, q) by rejection sampling
func SampleZq(rand io.Reader, q uint64) (res uint64) {
	for {
		var r uint64
		if err := readRandomBytes(rand, &r); err != nil {
			panic(err)
		}
		res = r % q
		if res < q {
			return
		}
	}
}

// readRandomBytes reads random bytes from the provided io.Reader into uint64
func readRandomBytes(r io.Reader, out *uint64) error {
	buf := make([]byte, 8) // uint64 is 8 bytes
	if _, err := r.Read(buf); err != nil {
		return err
	}
	*out = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 | uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	return nil
}

// RubSampleZqx Returns uniform random value in (0,q) by rejection sampling
func RubSampleZqx(rand io.Reader, q uint64) (res uint64) {
	bitLen := bits.Len64(q - 2)
	byteLen := (bitLen + 7) / 8
	b := bitLen % 8
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, byteLen)
	for {
		_, err := io.ReadFull(rand, bytes)
		if err != nil {
			panic(err)
		}
		bytes[byteLen-1] &= uint8((1 << b) - 1)

		res = 0
		for i := 0; i < byteLen; i++ {
			res += uint64(bytes[i]) << (8 * i)
		}

		if res < q {
			return
		}
	}
}
