package pkg

import (
	"runtime"
	"sync"
)

// ParallelConfig controls the degree of parallelism for FV cipher evaluators.
// A zero-value ParallelConfig (MaxWorkers == 0) runs all operations serially.
type ParallelConfig struct {
	// MaxWorkers is the maximum number of goroutines used for parallel sections.
	// 0 or negative selects serial execution.
	MaxWorkers int

	// Guard enforces a heap-memory ceiling before launching goroutines.
	// When the ceiling is exceeded, execution falls back to serial.
	// nil disables the memory check.
	Guard *MemGuard
}

// DefaultParallelConfig returns a config that uses all logical CPUs with no memory guard.
func DefaultParallelConfig() ParallelConfig {
	return ParallelConfig{MaxWorkers: runtime.GOMAXPROCS(0)}
}

// SerialConfig returns a fully serial config — no goroutines are launched.
func SerialConfig() ParallelConfig {
	return ParallelConfig{MaxWorkers: 0}
}

// parallelDo runs fn(i) for each index in [0, n) using at most maxWorkers goroutines.
//
// Fallback conditions (serial execution):
//   - maxWorkers <= 0, OR
//   - guard is non-nil and reports memory pressure.
//
// The first non-nil error returned by any fn call is returned; all remaining
// goroutines are allowed to complete before the error is propagated.
func parallelDo(n, maxWorkers int, guard *MemGuard, fn func(i int) error) error {
	if n == 0 {
		return nil
	}

	// Fall back to serial when parallelism is disabled or memory pressure is high.
	if maxWorkers <= 0 || (guard != nil && !guard.Allow()) {
		for i := 0; i < n; i++ {
			if err := fn(i); err != nil {
				return err
			}
		}
		return nil
	}

	workers := maxWorkers
	if workers > n {
		workers = n
	}

	sem := make(chan struct{}, workers) // counting semaphore
	errc := make(chan error, n)         // buffered so goroutines never block
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire worker slot (blocks if at capacity)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }() // release worker slot
			errc <- fn(idx)
		}(i)
	}

	wg.Wait()
	close(errc)

	for err := range errc {
		if err != nil {
			return err
		}
	}
	return nil
}
