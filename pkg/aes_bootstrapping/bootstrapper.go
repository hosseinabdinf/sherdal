package aes_bootstrapping

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

type Bootstrapper interface {

	// Bootstrap defines a method that takes a single Ciphertext as input and applies
	// an in place scheme-specific aes_bootstrapping. The result is also returned.
	// An error should notably be returned if ct.Level() < Bootstrapper.MinimumInputLevel().
	Bootstrap(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error)

	// BootstrapMany defines a method that takes a slice of Ciphertexts as input and applies an
	// in place scheme-specific aes_bootstrapping to each Ciphertext. The result is also returned.
	// An error should notably be returned if cts[i].Level() < Bootstrapper.MinimumInputLevel().
	BootstrapMany(cts []rlwe.Ciphertext) ([]rlwe.Ciphertext, error)

	// Depth is the number of levels consumed by the aes_bootstrapping circuit.
	// This value is equivalent to params.MaxLevel() - OutputLevel().
	Depth() int

	// MinimumInputLevel defines the minimum level that the ciphertext
	// must be at when given to the bootstrapper.
	// For the centralized aes_bootstrapping this value is usually zero.
	// For the collective aes_bootstrapping it is given by the user-defined
	// security parameters
	MinimumInputLevel() int

	// OutputLevel defines the level that the ciphertext will be at
	// after the aes_bootstrapping.
	// For the centralized aes_bootstrapping this value is the maximum
	// level minus the depth of the aes_bootstrapping circuit.
	// For the collective aes_bootstrapping this value is usually the
	// maximum level.
	OutputLevel() int
}
