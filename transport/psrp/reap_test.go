package psrp

import (
	"context"
	"runtime"
	"testing"
	"time"

	psrp "github.com/smnsjas/go-psrp/client"
)

// TestRunStampsLastUsed: a Run that checks a conn out of the pool must stamp
// its lastUsed on the way back in, regardless of outcome — that timestamp is
// the only signal the reaper (reapIdle, below) has for "is this shell still
// worth keeping warm?".
func TestRunStampsLastUsed(t *testing.T) {
	f := &fakeExec{result: &psrp.Result{}}
	c := &conn{
		exec: f,
		up:   true,
		build: func() (executor, error) {
			return &fakeExec{result: &psrp.Result{}}, nil
		},
		lastUsed: time.Now().Add(-time.Hour), // stale, must be refreshed
	}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- c

	before := time.Now()
	if _, err := tr.Run(context.Background(), encode("x"), nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	c.mu.Lock()
	got := c.lastUsed
	c.mu.Unlock()
	if got.Before(before) {
		t.Errorf("lastUsed = %s, want at or after %s (stamped when Run returned the conn)", got, before)
	}
}

// TestReapClosesIdleConnExactlyOnce: a connected conn that has sat idle
// longer than ReapAfter is closed exactly once, its executor replaced with a
// fresh one from build(), and marked not-connected — the release side of the
// leak fix. Close is what actually sends the WS-Man Delete; without it the
// shell would just sit there until its lease expires, exactly the mitigation
// this reaper supersedes.
func TestReapClosesIdleConnExactlyOnce(t *testing.T) {
	stale := &fakeExec{result: &psrp.Result{}}
	fresh := &fakeExec{result: &psrp.Result{}}
	built := 0
	c := &conn{
		exec: stale,
		up:   true,
		build: func() (executor, error) {
			built++
			return fresh, nil
		},
		lastUsed: time.Now().Add(-time.Hour),
	}
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.ReapAfter = 30 * time.Second
	tr := &Transport{cfg: cfg, idle: make(chan *conn, 1)}
	tr.idle <- c

	tr.reapIdle(time.Now())

	if stale.closeCalls != 1 {
		t.Errorf("stale.closeCalls = %d, want 1", stale.closeCalls)
	}
	if built != 1 {
		t.Errorf("build calls = %d, want 1", built)
	}
	c.mu.Lock()
	gotExec, gotUp := c.exec, c.up
	c.mu.Unlock()
	if gotExec != executor(fresh) {
		t.Error("c.exec was not replaced with the freshly built executor")
	}
	if gotUp {
		t.Error("c.up = true, want false (must reconnect lazily on next use)")
	}
}

// TestReapRebuiltConnReconnectsOnNextRun: after a reap, the next Run through
// that conn must reconnect (lazily, like any never-used conn) and succeed —
// reaping must never leave the conn permanently unusable.
func TestReapRebuiltConnReconnectsOnNextRun(t *testing.T) {
	stale := &fakeExec{result: &psrp.Result{}}
	fresh := &fakeExec{result: &psrp.Result{Output: []interface{}{"ok"}}}
	c := &conn{
		exec: stale,
		up:   true,
		build: func() (executor, error) {
			return fresh, nil
		},
		lastUsed: time.Now().Add(-time.Hour),
	}
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.ReapAfter = 30 * time.Second
	tr := &Transport{cfg: cfg, idle: make(chan *conn, 1)}
	tr.idle <- c

	tr.reapIdle(time.Now())

	res, err := tr.Run(context.Background(), encode("x"), nil)
	if err != nil {
		t.Fatalf("Run after reap: %v", err)
	}
	if res.Stdout != "ok" {
		t.Errorf("Stdout = %q, want %q (from the rebuilt client)", res.Stdout, "ok")
	}
	if fresh.connectCalls != 1 {
		t.Errorf("fresh.connectCalls = %d, want 1 (must reconnect lazily after a reap)", fresh.connectCalls)
	}
	if stale.calls != 0 {
		t.Errorf("stale.calls = %d, want 0 (the reaped client must never be used again)", stale.calls)
	}
}

// TestReapLeavesRecentlyUsedConnAlone: a conn used within the ReapAfter
// window must not be reaped — closing a shell still in active rotation
// would be a functional regression, not a fix.
func TestReapLeavesRecentlyUsedConnAlone(t *testing.T) {
	f := &fakeExec{result: &psrp.Result{}}
	built := 0
	c := &conn{
		exec: f,
		up:   true,
		build: func() (executor, error) {
			built++
			return &fakeExec{result: &psrp.Result{}}, nil
		},
		lastUsed: time.Now(),
	}
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.ReapAfter = 30 * time.Second
	tr := &Transport{cfg: cfg, idle: make(chan *conn, 1)}
	tr.idle <- c

	tr.reapIdle(time.Now())

	if f.closeCalls != 0 {
		t.Errorf("closeCalls = %d, want 0 (conn used within the window must not be reaped)", f.closeCalls)
	}
	if built != 0 {
		t.Errorf("build calls = %d, want 0", built)
	}
	c.mu.Lock()
	gotUp := c.up
	c.mu.Unlock()
	if !gotUp {
		t.Error("c.up = false, want true (untouched)")
	}
}

// TestReapNeverConnectedConnNotClosed: a conn that has never connected
// (up == false, e.g. straight from New(), or already invalidated/reaped by
// an earlier pass) must not be "closed" — there is no live shell behind it,
// and calling Close on an executor that was never Connect-ed is not a case
// any of this package's conn machinery is designed to handle safely (see
// conn.invalidate's own doc on why a dead/absent client is never Closed).
func TestReapNeverConnectedConnNotClosed(t *testing.T) {
	f := &fakeExec{result: &psrp.Result{}}
	built := 0
	c := &conn{
		exec: f,
		up:   false,
		build: func() (executor, error) {
			built++
			return &fakeExec{result: &psrp.Result{}}, nil
		},
		lastUsed: time.Now().Add(-time.Hour), // stale, but irrelevant: never connected
	}
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.ReapAfter = 30 * time.Second
	tr := &Transport{cfg: cfg, idle: make(chan *conn, 1)}
	tr.idle <- c

	tr.reapIdle(time.Now())

	if f.closeCalls != 0 {
		t.Errorf("closeCalls = %d, want 0 (never connected, nothing live to close)", f.closeCalls)
	}
	if built != 0 {
		t.Errorf("build calls = %d, want 0 (no spurious rebuild of an already-fresh conn)", built)
	}
	c.mu.Lock()
	gotExec := c.exec
	c.mu.Unlock()
	if gotExec != executor(f) {
		t.Error("c.exec was replaced even though the conn was never connected")
	}
}

// newRealTestTransport builds a Transport through the real New(), the only
// path that starts the reap goroutine — every other test in this package
// builds a Transport by struct literal specifically to avoid that goroutine,
// so the New/Close lifecycle gets its own real construction here. newClient
// (New's build closure) does no network I/O — it only builds a go-psrp
// client object — so this is safe to call in a unit test; a bogus host and
// throwaway credentials are enough to satisfy go-psrp's own Config.Validate.
func newRealTestTransport(t *testing.T, concurrency int) *Transport {
	t.Helper()
	tr, err := New(Config{
		Host:        "dc.invalid.test",
		Username:    "u",
		Password:    "p",
		Concurrency: concurrency,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr
}

// TestCloseStopsReapLoop: Close must not return until the reap goroutine has
// actually exited — asserted via reapDone closing, not assumed from Close
// merely returning without error. A goroutine that outlives Close is a
// leak: nothing else in this process will ever stop it (see the package
// doc's "no end-of-run hook" problem this whole feature exists to work
// around at the shell level; the same absence applies to the reaper's own
// goroutine, which is why Close must be the one thing that can stop it).
func TestCloseStopsReapLoop(t *testing.T) {
	tr := newRealTestTransport(t, 1)

	select {
	case <-tr.reapDone:
		t.Fatal("reapDone already closed before Close was ever called")
	default:
		// Expected: the loop is running.
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-tr.reapDone:
		// Expected: the loop observed reapStop and returned.
	case <-time.After(2 * time.Second):
		t.Fatal("reap goroutine did not stop within 2s of Close returning")
	}
}

// TestCloseReapLoopDoesNotLeakGoroutines is a second, independent proof
// alongside TestCloseStopsReapLoop: repeated create/Close cycles must not
// accumulate goroutines. Comparing counts is inherently a little noisy (the
// Go runtime has its own background goroutines that can come and go), so
// this asserts on the growth after many cycles against a small tolerance,
// not on an exact number, and gives the runtime a moment to settle before
// each measurement.
func TestCloseReapLoopDoesNotLeakGoroutines(t *testing.T) {
	settle := func() int {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		return runtime.NumGoroutine()
	}

	before := settle()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		tr := newRealTestTransport(t, 2)
		if err := tr.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
	}

	after := settle()
	const tolerance = 3
	if after > before+tolerance {
		t.Errorf("goroutines before=%d after=%d cycles=%d: grew by %d, want <= %d (reap goroutine leaking)",
			before, after, cycles, after-before, tolerance)
	}
}
