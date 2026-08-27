package warm

import (
	"context"
	"errors"
	"sync"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// conn is one pooled executor plus its lazy-connect state. Each conn wraps a
// separate Executor — a separate warm shell/process — which is what makes
// concurrent Runs safe (a warm runspace has no per-op isolation of its own).
type conn struct {
	build func() (Executor, error) // rebuilds a fresh executor; see invalidate (added in Task 2)
	exec  Executor
	mu    sync.Mutex
	up    bool
	// lastUsed is stamped by Run when it returns this conn to the idle pool
	// (success or failure — either way, this conn was just held and acted
	// on). The idle-shell reaper reads it to decide whether a conn resting
	// in the pool has gone unused long enough to release its shell; see
	// Params.ReapAfter and Pool.reapLoop (Task 3).
	lastUsed time.Time
}

func (c *conn) ensureConnected(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.up {
		return nil
	}
	if err := c.exec.Connect(ctx); err != nil {
		return &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Connect", Err: err}
	}
	c.up = true
	return nil
}

// invalidate discards the dead executor behind conn and replaces it with a
// freshly built one, then marks the conn as needing to (re)connect. Call it
// only when the shell itself is actually suspect: a dead or reaped shell
// must not go on reporting itself connected, or every later Run through this
// pooled conn would fail for the life of the process. Two different failure
// classes must NOT reach this call, for two different reasons: a busy-queue
// sentinel (KindTransient) means the shell is fine and nothing was even
// attempted, and a context cancellation or deadline (KindTransport, but see
// isCallerTimeout) means the caller gave up — that says nothing about the
// shell either. Run's call site checks both before invalidating.
//
// Simply flipping a local "connected" flag is not enough: a warm executor
// tracks its own internal connected state, set only by a successful Connect
// and cleared only by Disconnect or Close — nothing in a failed Execute call
// resets it, so the same executor would go on reporting itself connected
// forever even though its shell is gone, and a later Connect on it is a
// silent no-op. Recovery therefore has to build a brand-new executor, not
// Close-then-Connect the old one.
//
// The discarded executor is best-effort Closed first. For the winrm executor
// this is a near no-op (its shell is already gone server-side), but a
// process-backed executor (local/ssh warm) owns a live pwsh child, and simply
// dropping it would orphan that process. Closing the OLD, discarded object is
// always safe — we never reuse it, so the "Close permanently marks this object
// closed, breaking a later Connect on it" hazard does not apply; that hazard is
// exactly why we build a fresh executor rather than reviving this one. The
// Close is bounded by a short timeout so a hung child cannot stall recovery.
func (c *conn) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exec != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.exec.Close(ctx) // discarded object; releases an OS process, harmless for winrm
		cancel()
	}
	if fresh, err := c.build(); err == nil {
		c.exec = fresh
	}
	// If build itself fails, keep the old (dead) exec: ensureConnected will
	// try it again and Execute will fail the same way, surfacing a clear
	// error rather than leaving the conn in a half-built state.
	c.up = false
}

// isCallerTimeout answers a narrow but easily conflated question: what a
// failed Execute call driven by a caller context error means. A context
// error says only that the caller (or an ancestor context) stopped waiting —
// it carries no information about whether the shell that was mid-request is
// still alive. The shell is, if anything, probably still good: the caller
// gave up, the server did not refuse anything.
func isCallerTimeout(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
