package pkg_test

import (
	"testing"

	"github.com/hosseinabdinf/sherdal/hhe/hera"
	"github.com/hosseinabdinf/sherdal/hhe/rubato"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"
	symrubato "github.com/hosseinabdinf/sherdal/ske/rubato"

	"github.com/hosseinabdinf/sherdal/pkg"
	"github.com/stretchr/testify/require"
)

// TestBridgeRequiresAlignedRuntime verifies that NewBridge returns an error when
// the BGV runtime parameters do not match the residual CKKS parameters.
// This test is fast — it builds a non-residual Hera (BGV key gen only).
func TestBridgeRequiresAlignedRuntime(t *testing.T) {
	heHera, err := hera.NewHera(hera.Config{Preset: hera.Hera128AF, BGVLogN: 14, SymmetricParams: symhera.Hera4Params2516})
	require.NoError(t, err)

	_, err = heHera.NewBridge()
	require.Error(t, err)
}

// TestBridgeBuildsHalfBootInput verifies that the RtFBridge correctly constructs
// a half-bootstrapping input ciphertext.
//
// The expensive CKKS bootstrapping key generation (NewHalfBootstrapper, ~60 s)
// is NOT part of this test — it lives in TestHalfBootstrapperBuildsWithResidualBGV.
// This test exercises only the bridge arithmetic and completes in < 5 s.
func TestBridgeBuildsHalfBootInput(t *testing.T) {
	requireSharedBridge(t) // ~1-2 s on first call, free on subsequent calls

	coeffCipher, err := sharedBridge.EncryptCoefficientCiphertext(make([]uint64, sharedBridge.ResidualN()))
	require.NoError(t, err)

	values := pkg.PackCoefficientsBitReversed([]float64{0.25, -0.5, 0.75, 0.0}, 2)
	ct, err := sharedBridge.BuildHalfBootInput(values, coeffCipher)
	require.NoError(t, err)
	require.Equal(t, 0, ct.Level())
	require.True(t, ct.IsNTT)
	require.Equal(t, sharedBridge.InputScale(), ct.Scale.Float64())
}

// TestHalfBootstrapperBuildsWithResidualBGV verifies that NewHalfBootstrapper
// succeeds when called on a UseResidualBGV Hera instance and that the resulting
// bootstrapper is fully initialised.
//
// This test is intentionally expensive (~60 s) because it triggers CKKS
// bootstrapping evaluation-key generation inside the lattigo library — a
// one-time setup cost that cannot be parallelised from this layer.
// Skip it with -short for fast CI runs:
//
//	go test ./pkg/... -short
func TestHalfBootstrapperBuildsWithResidualBGV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive CKKS bootstrapping key generation (-short flag)")
	}

	requireSharedHalfBootstrapper(t) // builds sharedBridge too if needed

	require.NotNil(t, sharedHalfBootstrapper)
	require.NotNil(t, sharedHalfBootstrapper.Runtime())
	require.NotNil(t, sharedHalfBootstrapper.Runtime().Bootstrapper)
}

func TestRubatoEvalKeystreamCoeffsSmoke(t *testing.T) {
	heRubato, err := rubato.NewRubato(rubato.Config{Preset: rubato.Rubato128S, UseResidualBGV: true, SymmetricParams: symrubato.Parameter{LogN: 16, BlockSize: 16, Modulus: symrubato.Rubato5Param2616.Modulus, Rounds: 2, Sigma: 0}})
	require.NoError(t, err)

	key := []uint64{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16}
	require.NoError(t, heRubato.EncryptSymmetricKey(key))

	cts, err := heRubato.EvalKeystreamCoeffs(pkg.DeterministicNonces(1, 8), []byte{0, 1, 2, 3, 4, 5, 6, 7})
	require.NoError(t, err)
	require.Len(t, cts, 12)
	for _, ct := range cts {
		require.NotNil(t, ct)
	}
}
