package psrp

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
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

// TestReapInterval pins reapInterval's two documented properties: it scales
// with ReapAfter (so a shell goes idle-then-reaped within roughly ReapAfter
// plus one tick, not on some unrelated cadence) and it never goes below one
// second — the floor that keeps an aggressively small ReapAfter from turning
// the reaper into a busy-loop. Neither was asserted anywhere before this.
func TestReapInterval(t *testing.T) {
	tests := []struct {
		name      string
		reapAfter time.Duration
		want      time.Duration
	}{
		{"scales at ReapAfter/4", 8 * time.Second, 2 * time.Second},
		{"the 30s default scales to 7.5s", 30 * time.Second, 7500 * time.Millisecond},
		{"zero floors at 1s", 0, time.Second},
		{"a tiny ReapAfter floors at 1s", 20 * time.Millisecond, time.Second},
		{"exactly at the floor boundary stays at 1s", 4 * time.Second, time.Second},
		{"just past the boundary scales, not floors", 4*time.Second + 4*time.Millisecond, time.Second + time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reapInterval(tt.reapAfter); got != tt.want {
				t.Errorf("reapInterval(%s) = %s, want %s", tt.reapAfter, got, tt.want)
			}
		})
	}
}

// newStressTestTransport builds a Transport the same way New() does —
// reapStop/reapDone wired, reapLoop actually started — but with fakeExec
// clients instead of real go-psrp ones, so it can be driven concurrently at
// speed. It exists specifically for TestReapAndRunUnderConcurrentStress:
// every other test in this file that starts the real goroutine
// (newRealTestTransport) creates and immediately Closes without ever
// calling Run, so nothing before this test actually overlaps the reaper
// with an in-flight Run in time — every reap-behavior test above calls
// reapIdle synchronously and sequentially with Run, never concurrently.
func newStressTestTransport(cfg Config) *Transport {
	cfg = cfg.WithDefaults()
	tr := &Transport{
		cfg:      cfg,
		idle:     make(chan *conn, cfg.Concurrency),
		reapStop: make(chan struct{}),
		reapDone: make(chan struct{}),
	}
	build := func() (executor, error) { return &fakeExec{result: &psrp.Result{}}, nil }
	for i := 0; i < cfg.Concurrency; i++ {
		// Mirrors New()'s own construction: every conn needs a non-nil exec
		// from the start (up stays false, so it connects lazily on first
		// use, exactly like a real pool) — a conn built with a nil exec is
		// not a state Run or the reaper is ever meant to encounter.
		c, err := build()
		if err != nil {
			panic(err) // build() above never errors; a test-only invariant
		}
		tr.idle <- &conn{exec: c, build: build}
	}
	go tr.reapLoop()
	return tr
}

// TestReapAndRunUnderConcurrentStress drives Run and the real reap
// goroutine against each other for real wall-clock time, then Closes — the
// gap every other test in this file leaves open: they either call reapIdle
// synchronously and sequentially with Run (never overlapping in time), or
// start the real goroutine and Close immediately without issuing any Runs.
// The properties argued for in reapIdle/reapConnIfIdle/Close's own
// comments — that the reaper can never observe a conn a Run holds, can
// never block a Run, and that Close cannot race a sweep in flight — are
// checked here under actual concurrent scheduling, not only by inspection.
// -race is what makes this test meaningful: it cannot catch a defect in an
// interaction no test actually drives concurrently.
//
// ReapAfter is set small so that once the reaper's ticker does fire, every
// conn in the pool is already well past its window and eligible. But
// reapInterval floors at one second regardless of how small ReapAfter is
// (see TestReapInterval), so the first sweep cannot happen before roughly a
// second in — the stress window below is sized past that floor
// deliberately, not left at some shorter "a few hundred milliseconds"
// figure, specifically so a real sweep is overwhelmingly likely to land
// while Runs are still in flight, rather than merely coexisting with a
// reaper that never actually wakes during the window.
//
// Every assertion below is on a property that must hold no matter how the
// scheduler interleaves things — never on a particular interleaving having
// occurred — because the interleaving itself is not something a test can
// control or observe deterministically.
func TestReapAndRunUnderConcurrentStress(t *testing.T) {
	// Concurrency 1 is the configuration where a reap in progress and a Run
	// genuinely compete for the only conn in the pool, rather than one of
	// several; both are worth covering.
	for _, concurrency := range []int{4, 1} {
		t.Run(fmt.Sprintf("Concurrency=%d", concurrency), func(t *testing.T) {
			testReapAndRunUnderConcurrentStress(t, concurrency)
		})
	}
}

func testReapAndRunUnderConcurrentStress(t *testing.T, concurrency int) {
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.Concurrency = concurrency
	cfg.ReapAfter = 30 * time.Millisecond
	tr := newStressTestTransport(cfg)

	const window = 1300 * time.Millisecond // past reapInterval's 1s floor
	deadline := time.Now().Add(window)

	const workers = 8
	var wg sync.WaitGroup
	var totalRuns int64
	var badMu sync.Mutex
	var badErrs []error

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_, err := tr.Run(context.Background(), encode("x"), nil)
				atomic.AddInt64(&totalRuns, 1)
				if err != nil {
					badMu.Lock()
					if len(badErrs) < 20 {
						badErrs = append(badErrs, err)
					}
					badMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if len(badErrs) > 0 {
		// Every Run here runs against a fakeExec that never returns an
		// error and never fails to Connect, and Run's checkout uses
		// context.Background() (never cancelled), so the "pool busy"
		// ctx.Done() path can never fire either. The only way a Run could
		// observe an error in this test is a pool-ownership violation — the
		// reaper and a Run both touching the same conn at once — which is a
		// correctness bug, not a legitimate transient condition to filter
		// by Kind.
		t.Errorf("%d/%d Run calls failed; first few: %v", len(badErrs), totalRuns, badErrs)
	}
	if totalRuns == 0 {
		t.Fatal("no Run calls completed; the stress loop did not run")
	}
	t.Logf("concurrency=%d total Run calls=%d", concurrency, totalRuns)

	// Pool capacity intact: drain exactly `concurrency` distinct conns back
	// out, with a bound on each receive so a reaper that is (legitimately)
	// still mid-sweep does not hang the test — reapConnIfIdle's own work
	// against a fakeExec is effectively instant, so this bound is generous,
	// not tight.
	seen := make(map[*conn]bool, concurrency)
	drained := make([]*conn, 0, concurrency)
	for i := 0; i < concurrency; i++ {
		select {
		case c := <-tr.idle:
			if seen[c] {
				t.Fatalf("conn %p received twice while draining the pool", c)
			}
			seen[c] = true
			drained = append(drained, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("pool has fewer than %d conns after the stress run (drained %d)", concurrency, len(drained))
		}
	}
	select {
	case c := <-tr.idle:
		t.Fatalf("pool has more than %d conns after the stress run (extra: %p)", concurrency, c)
	default:
		// Expected: exactly `concurrency` conns total, no extras conjured
		// and none lost.
	}
	for _, c := range drained {
		tr.idle <- c // restore before Close, which itself expects to drain exactly Concurrency conns
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- tr.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5s (reaper likely failed to stop, or deadlocked against the drain)")
	}
}
