package internal

import (
	"testing"

	symhera "github.com/hosseinabdinf/sherdal/ske/hera"

	"github.com/hosseinabdinf/sherdal/hhe/hera"

	"github.com/stretchr/testify/require"
)

func TestHalfBootstrapRuntimeBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy halfboot runtime generation in short mode")
	}
	if testing.Verbose() == false {
		t.Skip("enable with go test -v when validating the aes_bootstrapping runtime")
	}

	hb, err := NewHalfBootstrapper(hera.DefaultHeraConfig(hera.Hera128AF, symhera.Hera4Params2516).HalfBootSpec())
	require.NoError(t, err)
	require.NotNil(t, hb.Runtime().Bootstrapper)
}
