package warm

import (
	"sync"
	"time"
)

// conn is one pooled executor plus its lazy-connect state. Each conn wraps a
// separate Executor — a separate warm shell/process — which is what makes
// concurrent Runs safe (a warm runspace has no per-op isolation of its own).
type conn struct {
	build    func() (Executor, error) // rebuilds a fresh executor; see invalidate (added in Task 2)
	exec     Executor
	mu       sync.Mutex
	up       bool
	lastUsed time.Time
}
