package internal

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

type TranscipherResult struct {
	Keystream        []*rlwe.Ciphertext
	KeystreamCoeffs  []*rlwe.Ciphertext
	ClientPlaintext  *rlwe.Plaintext
	HalfBootInput    *rlwe.Ciphertext
	HalfBootstrapper *HalfBootstrapper
	HalfBootReal     *rlwe.Ciphertext
	HalfBootImag     *rlwe.Ciphertext
}
