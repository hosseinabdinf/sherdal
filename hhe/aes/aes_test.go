package aes

import (
	"bytes"
	stdaes "crypto/aes"
	"crypto/cipher"
	"math"
	aesbootstrapper "sherdal/internal/aes_bootstrapping"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestCTRBitSetCounterMatchesStandardIncrement(t *testing.T) {
	iv := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	ivBitSet := NewBitSet(128)
	ivBitSet.SetBytes(iv)

	cases := []struct {
		counter uint64
		expect  []byte
	}{
		{counter: 0, expect: append([]byte(nil), iv...)},
		{counter: 1, expect: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xff}},
		{counter: 2, expect: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdd, 0x00}},
	}

	for _, tc := range cases {
		got := ctr(ivBitSet, tc.counter).ToBytes()
		if !bytes.Equal(got, tc.expect) {
			t.Fatalf("counter %d mismatch: got %x, want %x", tc.counter, got, tc.expect)
		}
	}
}

func TestAESCtrTranscipherMatchesStandardAESCTR(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy HE AES integration test in short mode")
	}
	//if os.Getenv("SHERDAL_RUN_HE_AES_INTEGRATION") != "1" {
	//	t.Skip("set SHERDAL_RUN_HE_AES_INTEGRATION=1 to run heavy HE AES integration test")
	//}

	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	iv := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	plaintext := []byte("Check Sherdal's HE AES implementation against the AES-CTR standard.")

	blk, err := stdaes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating AES cipher failed: %v", err)
	}
	stream := cipher.NewCTR(blk, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	params, btpParams := newHEAESParams(t)

	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)

	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		t.Fatalf("generating evaluation keys failed: %v", err)
	}

	heAES, err := NewAESCtr(key, params, btpParams, evk, encoder, encryptor, decryptor, iv)
	if err != nil {
		t.Fatalf("creating HE AES failed: %v", err)
	}

	heOut := heAES.HEDecrypt(ciphertext, len(plaintext)*8)
	recovered := decodePackedBitCiphertexts(t, heOut, decryptor, encoder, params, len(plaintext)*8)

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("AES transcipher mismatch\nwant: %x\n got: %x", plaintext, recovered)
	}

	//t.Logf("Sym Ciphertext: %x", ciphertext)
	//t.Logf("HE Ciphertext: %+v", heOut[0])
	t.Logf("AES transcipher matches\nwant: %s\n got: %s", plaintext, recovered)
}

func decodePackedBitCiphertexts(t *testing.T, state []*rlwe.Ciphertext, decryptor *rlwe.Decryptor, encoder *ckks.Encoder, params ckks.Parameters, bits int) []byte {
	t.Helper()

	numBlocks := int(math.Ceil(float64(bits) / 128.0))
	out := make([]byte, int(math.Ceil(float64(bits)/8.0)))

	for bitIdx := 0; bitIdx < 128; bitIdx++ {
		if state[bitIdx] == nil {
			t.Fatalf("nil ciphertext for bit index %d", bitIdx)
		}

		decoded := make([]float64, params.MaxSlots())
		encoder.Decode(decryptor.DecryptNew(state[bitIdx]), decoded)

		for block := 0; block < numBlocks; block++ {
			globalBit := block*128 + bitIdx
			if globalBit >= bits {
				continue
			}

			if decoded[block] > 0.5 {
				out[globalBit/8] |= 1 << uint(globalBit%8)
			}
		}
	}

	return out
}

func newHEAESParams(t *testing.T) (ckks.Parameters, aesbootstrapper.Parameters) {
	t.Helper()

	const logN = 9

	q0 := []int{58}
	qiSlotsToCoeffs := []int{42, 42, 42}
	qiCircuitSlots := []int{42, 42, 42, 42, 42, 42, 42, 42, 42}
	qiEvalMod := []int{58, 58, 58, 58, 58, 58, 58, 58}
	qiCoeffsToSlots := []int{58, 58, 58, 58}

	logQ := append(q0, qiSlotsToCoeffs...)
	logQ = append(logQ, qiCircuitSlots...)
	logQ = append(logQ, qiEvalMod...)
	logQ = append(logQ, qiCoeffsToSlots...)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            logN,
		LogQ:            logQ,
		LogP:            []int{59, 59, 60, 60, 60},
		LogDefaultScale: 42,
		Xs:              ring.Ternary{H: 192},
	})
	if err != nil {
		t.Fatalf("creating CKKS parameters failed: %v", err)
	}

	coeffsToSlots := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal,
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: 1,
		Levels:       []int{1, 1, 1, 1},
	}

	mod1Literal := mod1.ParametersLiteral{
		LevelQ:          params.MaxLevel() - coeffsToSlots.Depth(true),
		LogScale:        58,
		Mod1Type:        mod1.CosDiscrete,
		Mod1Degree:      30,
		DoubleAngle:     3,
		K:               16,
		LogMessageRatio: 10,
		Mod1InvDegree:   0,
	}

	slotsToCoeffs := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: 1,
		LevelP:       params.MaxLevelP(),
		Levels:       []int{1, 1, 1},
	}
	slotsToCoeffs.LevelQ = len(slotsToCoeffs.Levels)

	bParams := aesbootstrapper.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: slotsToCoeffs,
		Mod1ParametersLiteral:   mod1Literal,
		CoeffsToSlotsParameters: coeffsToSlots,
		EphemeralSecretWeight:   32,
		CircuitOrder:            aesbootstrapper.DecodeThenModUp,
	}

	return params, bParams
}
