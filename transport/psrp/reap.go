package psrp

import (
	"context"
	"time"
)

// This file is the release side of the shell-leak fix. Nothing else in this
// package ever deletes a shell it opened: Config.IdleTimeout only bounds how
// long an abandoned shell survives before the *server* reaps it, and
// conn.invalidate (psrp.go) explicitly never closes the executor it
// replaces, because it only ever runs on a shell already dead server-side.
// This reaper is the one piece of the pool that closes a shell that is still
// alive — the WS-Man Delete that actually releases it — for the common case
// where nothing tells this package the run is over: it just notices a conn
// has gone unused and lets it go.

// reapInterval picks how often the background reaper wakes to sweep the
// pool. It scales with ReapAfter (so a shell goes idle-then-reaped within
// roughly ReapAfter plus one tick, not on some unrelated fixed cadence) but
// is never faster than one second — without that floor, an aggressively
// small ReapAfter (a test, or a misconfiguration) would turn the reaper into
// a busy-loop rather than a periodic sweep.
func reapInterval(reapAfter time.Duration) time.Duration {
	iv := reapAfter / 4
	if iv < time.Second {
		iv = time.Second
	}
	return iv
}

// reapLoop is the Transport's one background goroutine, started by New and
// stopped by Close. It wakes on a ticker and, each time, calls reapIdle to
// sweep whatever conns are currently resting in the pool. Close signals
// reapStop and waits for reapDone to close before doing anything else — see
// Close's own comment for why that ordering, not the sweep loop, is what
// makes Close-racing-a-sweep safe.
func (t *Transport) reapLoop() {
	defer close(t.reapDone)
	ticker := time.NewTicker(reapInterval(t.cfg.ReapAfter))
	defer ticker.Stop()
	for {
		select {
		case <-t.reapStop:
			return
		case now := <-ticker.C:
			t.reapIdle(now)
		}
	}
}

// reapIdle sweeps the pool once: for every conn currently resting in the
// idle channel, close and rebuild it if it has gone unused for at least
// ReapAfter.
//
// Contention with Run: the reaper checks a conn out of the idle pool with a
// NON-blocking receive, using the exact same channel Run checks out from
// (blocking). Go's channel semantics guarantee a given buffered value is
// delivered to exactly one receiver, so whichever of Run or the reaper
// actually receives a particular *conn owns it exclusively until it is sent
// back — the reaper can never observe, let alone reap, a conn that a Run
// currently holds (it is simply absent from the channel while checked out),
// and it can never make a Run wait: the reaper never blocks trying to send a
// conn back (the channel is exactly Concurrency deep and this loop always
// returns what it just took before taking another) and never blocks trying
// to receive one (the `default` case below just ends the sweep instead of
// waiting for one to become available).
//
// n is snapshotted once from len(t.idle) at the start of the sweep, so the
// loop visits at most as many conns as were actually resting in the pool
// when the sweep began. Without that snapshot a naive "loop while something
// is available" could spin far longer than one pass' worth of work if a
// concurrent Run keeps returning (and this same sweep keeps re-taking) one
// conn while others are checked out elsewhere — n bounds the sweep to one
// pass over what was actually idle, not an unbounded chase.
func (t *Transport) reapIdle(now time.Time) {
	for i, n := 0, len(t.idle); i < n; i++ {
		select {
		case c := <-t.idle:
			t.reapConnIfIdle(c, now)
			t.idle <- c
		default:
			// Nothing left to receive without blocking: every conn the
			// snapshot counted is either already back in the channel or is
			// (again) checked out by a Run. Either way, this sweep is done;
			// the next tick picks up where this one left off.
			return
		}
	}
}

// reapConnIfIdle is the live-shell counterpart to conn.invalidate. invalidate
// handles a shell already dead server-side and deliberately never closes the
// old executor — closing a client whose shell is already gone would brick
// it, per invalidate's own doc. reapConnIfIdle handles the opposite case: the
// shell is alive, so it must call Close, which is what actually sends the
// WS-Man Delete and releases it — the entire point of this mechanism.
//
// The caller (reapIdle) guarantees exclusive ownership of c for the duration
// of this call (c is out of the idle channel), so nothing else can be
// touching c concurrently — Run cannot, because it does not have this *conn;
// Transport.Close cannot, for the same reason (see Close's own comment). The
// lock is still taken, both for consistency with every other conn method
// (ensureConnected holds it across its own blocking Connect call the same
// way) and because c's fields must become visible to whichever goroutine
// checks this conn out next, on a different M — a plain unsynchronized write
// here would be a data race even though no other goroutine holds this
// specific *conn at the same time.
func (t *Transport) reapConnIfIdle(c *conn, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.up {
		// Never connected (fresh from New, or already invalidated/reaped by
		// an earlier pass): there is no live shell behind it to release.
		return
	}
	if now.Sub(c.lastUsed) < t.cfg.ReapAfter {
		// Used recently enough; leave the warm shell alone. Reaping a conn
		// still in active rotation would be a functional regression, not a
		// fix — the entire reason clients are kept warm in the first place.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
	// Best-effort: a failed Close still means this executor's shell state is
	// no longer trustworthy, so the conn is rebuilt exactly as if Close had
	// succeeded. Refusing to swap in a fresh executor on a Close error would
	// leave c.up correctly false but c.exec pointing at a client in unknown
	// condition — strictly worse than just replacing it, and inconsistent
	// with how invalidate already treats its own analogous failure mode.
	_ = c.exec.Close(ctx)
	cancel()

	if fresh, err := c.build(); err == nil {
		c.exec = fresh
	}
	// If build itself fails, keep the old (now-closed) exec, mirroring
	// invalidate: the next ensureConnected's Connect call will fail loudly
	// against it, surfacing a clear error rather than leaving the conn in a
	// half-built state.
	c.up = false
}
