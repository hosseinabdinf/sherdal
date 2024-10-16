package applications

import (
	"fmt"
	"testing"
)

func BenchmarkBWFilterCKKS(b *testing.B) {
	for _, tc := range TestVector {
		fmt.Printf("\n ---*** BW Filter CKKS Test #%d, logN=%d, img:%s ***--- \n", tc.t, tc.paramsLiteral.LogN, tc.imageName)
		benchmarkBWFilterCKKS(b, tc)
	}
}

func benchmarkBWFilterCKKS(b *testing.B, tc TestContext) {
	b.ResetTimer()
	b.Run("Benchmark BWFilter CKKS", func(b *testing.B) {
		BWFilterCKKS(tc.imageName, tc.paramsLiteral, false)
	})
}
