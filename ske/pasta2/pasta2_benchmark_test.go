package pasta2

import (
	"crypto/rand"
	"testing"

	"github.com/hosseinabdinf/sherdal/ske"
	"github.com/hosseinabdinf/sherdal/utils"
)

type TestContext struct {
	Params Parameter
}

var pasta3TestVector = []TestContext{
	{
		Params: Pasta3Param1614,
	}, {
		Params: Pasta3Param3215,
	}, {
		Params: Pasta3Param6015,
	},
}

var pasta4TestVector = []TestContext{
	{
		Params: Pasta4Param1614,
	}, {
		Params: Pasta4Param3215,
	}, {
		Params: Pasta4Param6015,
	},
}

func BenchmarkPasta2_3(b *testing.B) {
	for _, tc := range pasta3TestVector {
		benchmarkPasta2(&tc, b)
	}
}

func BenchmarkPasta2_4(b *testing.B) {
	for _, tc := range pasta4TestVector {
		benchmarkPasta2(&tc, b)
	}
}

func benchmarkPasta2(tc *TestContext, b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	logger := utils.NewLogger(utils.DEBUG)
	logger.PrintFormatted("[Rounds=%d | Modulus=%d | KeySize=%d | BlockSize=%d]", tc.Params.Rounds, tc.Params.Modulus, tc.Params.KeySize, tc.Params.BlockSize)

	var encryptor Encryptor
	var key ske.Key
	var symPasta Pasta2
	var plaintext ske.Plaintext
	var ciphertext ske.Ciphertext

	// generate symmetric key
	b.Run("Pasta2SymKeyGen", func(b *testing.B) {
		key = GenerateSymKey(tc.Params)
	})

	b.Run("Pasta2/NewPasta2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			symPasta = NewPasta2(key, tc.Params)
		}
	})

	b.Run("Pasta2/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = symPasta.NewEncryptor()
		}
	})

	numBlocks := 10
	maxSlot := tc.Params.GetBlockSize() * numBlocks
	// generate random plaintext
	plaintext = make(ske.Plaintext, maxSlot)
	for i := 0; i < maxSlot; i++ {
		plaintext[i] = utils.SampleZq(rand.Reader, tc.Params.GetModulus())
	}

	b.Run("Pasta2/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ciphertext = encryptor.Encrypt(plaintext)
		}
	})

	b.Run("Pasta2/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(ciphertext)
		}
	})
}
