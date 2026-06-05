package pkg

import (
	"fmt"
	"runtime"
)

// MemGuard enforces a soft memory ceiling before allowing new parallel work to start.
// It reads runtime heap statistics at task boundaries — not in tight inner loops — to
// avoid excessive stop-the-world GC pauses.
type MemGuard struct {
	softLimitBytes uint64
}

// NewMemGuard creates a MemGuard whose soft limit is 80 % of the supplied hard limit.
// Pass 0 to create a guard that never triggers (always allows).
func NewMemGuard(hardLimitBytes uint64) *MemGuard {
	if hardLimitBytes == 0 {
		return &MemGuard{softLimitBytes: ^uint64(0)} // never triggers
	}
	return &MemGuard{softLimitBytes: hardLimitBytes * 80 / 100}
}

// HeapInUse returns the current heap bytes in use via runtime.ReadMemStats.
//
// WARNING: runtime.ReadMemStats triggers a stop-the-world GC pause.
// Call this at task boundaries only — never inside tight inner loops.
func HeapInUse() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// Allow returns true when the current heap-in-use is below the soft limit.
// A nil receiver always returns true.
func (g *MemGuard) Allow() bool {
	if g == nil {
		return true
	}
	return HeapInUse() < g.softLimitBytes
}

// MustAllow returns an error if memory is at or above the soft limit.
// A nil receiver always returns nil.
func (g *MemGuard) MustAllow() error {
	if g == nil {
		return nil
	}
	if !g.Allow() {
		return fmt.Errorf("memory pressure: heap in-use exceeds soft limit of %d bytes", g.softLimitBytes)
	}
	return nil
}
