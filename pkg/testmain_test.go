package pkg_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/hosseinabdinf/sherdal/hhe/hera"
	"github.com/hosseinabdinf/sherdal/pkg"
	symhera "github.com/hosseinabdinf/sherdal/ske/hera"
)

// ---------------------------------------------------------------------------
// Shared expensive state — initialised lazily via sync.Once.
//
// Background: building a UseResidualBGV Hera instance requires two slow steps:
//
//  1. NewHera(UseResidualBGV:true) + NewBridge()  — ~1-2 s (BGV key gen)
//  2. NewHalfBootstrapper()                        — ~60 s  (CKKS bootstrapping
//                                                            evaluation keys)
//
// We separate these into two independently cached objects so that tests which
// only need the bridge (e.g. TestBridgeBuildsHalfBootInput) do not pay the 60 s
// bootstrapping cost, and tests that need the half-bootstrapper can be skipped
// with -short.
// ---------------------------------------------------------------------------

var (
	// bridge-level shared state (fast to build, ~1-2 s)
	bridgeOnce    sync.Once
	bridgeInitErr error
	sharedHera    *hera.Hera
	sharedBridge  *pkg.RtFBridge

	// half-bootstrapper shared state (slow to build, ~60 s)
	halfBootOnce           sync.Once
	halfBootInitErr        error
	sharedHalfBootstrapper *pkg.HalfBootstrapper
)

// initSharedBridge builds sharedHera and sharedBridge exactly once per binary
// run. This is cheap (BGV key generation only, <2 s).
func initSharedBridge() {
	bridgeOnce.Do(func() {
		h, err := hera.NewHera(hera.Config{
			Preset:          hera.Hera128AF,
			UseResidualBGV:  true,
			SymmetricParams: symhera.Hera4Params2516,
		})
		if err != nil {
			bridgeInitErr = fmt.Errorf("NewHera(residual): %w", err)
			return
		}
		sharedHera = h

		b, err := h.NewBridge()
		if err != nil {
			bridgeInitErr = fmt.Errorf("NewBridge: %w", err)
			return
		}
		sharedBridge = b
	})
}

// initSharedHalfBootstrapper builds sharedHalfBootstrapper exactly once per
// binary run. It calls initSharedBridge first to reuse the same Hera instance.
// This is expensive (~60 s) because it generates CKKS bootstrapping evaluation
// keys entirely inside the lattigo library — there is nothing to parallelise on
// our side.
func initSharedHalfBootstrapper() {
	halfBootOnce.Do(func() {
		// Guarantee the bridge (and sharedHera) exists first.
		initSharedBridge()
		if bridgeInitErr != nil {
			halfBootInitErr = bridgeInitErr
			return
		}

		hb, err := sharedHera.NewHalfBootstrapper()
		if err != nil {
			halfBootInitErr = fmt.Errorf("NewHalfBootstrapper: %w", err)
			return
		}
		sharedHalfBootstrapper = hb
	})
}

// requireSharedBridge ensures the bridge is initialised and fails t if it is not.
func requireSharedBridge(t *testing.T) {
	t.Helper()
	initSharedBridge()
	if bridgeInitErr != nil {
		t.Fatalf("shared bridge setup failed: %v", bridgeInitErr)
	}
}

// requireSharedHalfBootstrapper ensures the half-bootstrapper is initialised
// and fails t if it is not.
func requireSharedHalfBootstrapper(t *testing.T) {
	t.Helper()
	initSharedHalfBootstrapper()
	if halfBootInitErr != nil {
		t.Fatalf("shared half-bootstrapper setup failed: %v", halfBootInitErr)
	}
}
