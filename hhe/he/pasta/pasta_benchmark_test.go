package pasta

import (
	"encoding/binary"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"sherdal/utils"
	"testing"
)

func BenchmarkPasta3(b *testing.B) {
	// comment below loop if you want to go over each testcase manually
	// it helps to get benchmark results when there's memory limit in
	// your test environment
	for _, tc := range pasta3TestVector {
		benchHEPasta(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-2]
	//benchHEPasta(pasta3TestVector[0], b)
}

func BenchmarkPasta4(b *testing.B) {
	// comment below loop if you want to go over each testcase manually
	// it helps to get benchmark results when there's memory limit in
	// your test environment
	for _, tc := range pasta4TestVector {
		benchHEPasta(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-2]
	//benchHEPasta(pasta4TestVector[0], b)
}

func benchHEPasta(tc TestContext, b *testing.B) {
	//fmt.Println(testString("PASTA", tc.SymParams))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintDataLen(tc.Key)

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	b.Run("PASTA/HEKeyGen", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePasta.HEKeyGen()
		}
	})

	_ = hePasta.InitFvPasta()

	b.Run("PASTA/GaloisKeysGen", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePasta.CreateGaloisKeys(len(tc.ExCiphertext))
		}
	})

	//encrypts symmetric master key using BFV on the client side
	b.Run("PASTA/EncryptSymKey", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePasta.EncryptSymKey(tc.Key)
		}
	})

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	var fvCiphers []*rlwe.Ciphertext
	b.Run("PASTA/Transcipher", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fvCiphers = hePasta.Transcipher(nonce, tc.ExCiphertext)
		}
	})

	b.Run("PASTA/Decrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hePasta.Decrypt(fvCiphers[0])
		}
	})
}
