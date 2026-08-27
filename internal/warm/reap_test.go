package warm

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// newDirectPoolReap is newDirectPool with a caller-supplied ReapAfter: the
// reap tests below call p.reapIdle directly, and reapConnIfIdle's idle-window
// comparison (now.Sub(c.lastUsed) < t.params.ReapAfter) is meaningless
// against the zero value newDirectPool otherwise leaves it at.
func newDirectPoolReap(c *conn, cl Classifier, reapAfter time.Duration) *Pool {
	p := &Pool{
		params: Params{
			Classifier:  cl,
			Wrapper:     identityWrapper,
			Timeout:     2 * time.Second,
			Concurrency: 1,
			ReapAfter:   reapAfter,
		},
		idle: make(chan *conn, 1),
	}
	p.idle <- c
	return p
}

// TestRunStampsLastUsed: a Run that checks a conn out of the pool must stamp
// its lastUsed on the way back in, regardless of outcome — that timestamp is
// the only signal the reaper (reapIdle, below) has for "is this shell still
// worth keeping warm?".
func TestRunStampsLastUsed(t *testing.T) {
	f := &fakeExec{result: adpwsh.Result{}}
	c := &conn{
		exec: f,
		up:   true,
		build: func() (Executor, error) {
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
		lastUsed: time.Now().Add(-time.Hour), // stale, must be refreshed
	}
	p := newDirectPool(c, fakeClassifier{})

	before := time.Now()
	if _, err := p.Run(context.Background(), mustEncode(t, "x"), nil); err != nil {
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
// leak fix. Close is what actually releases the shell server-side; without it
// the shell would just sit there until its lease expires, exactly the
// mitigation this reaper supersedes.
func TestReapClosesIdleConnExactlyOnce(t *testing.T) {
	stale := &fakeExec{result: adpwsh.Result{}}
	fresh := &fakeExec{result: adpwsh.Result{}}
	built := 0
	c := &conn{
		exec: stale,
		up:   true,
		build: func() (Executor, error) {
			built++
			return fresh, nil
		},
		lastUsed: time.Now().Add(-time.Hour),
	}
	p := newDirectPoolReap(c, fakeClassifier{}, 30*time.Second)

	p.reapIdle(time.Now())

	stale.mu.Lock()
	gotCloses := stale.closes
	stale.mu.Unlock()
	if gotCloses != 1 {
		t.Errorf("stale.closes = %d, want 1", gotCloses)
	}
	if built != 1 {
		t.Errorf("build calls = %d, want 1", built)
	}
	c.mu.Lock()
	gotExec, gotUp := c.exec, c.up
	c.mu.Unlock()
	if gotExec != Executor(fresh) {
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
	stale := &fakeExec{result: adpwsh.Result{}}
	fresh := &fakeExec{result: adpwsh.Result{Stdout: "ok"}}
	c := &conn{
		exec: stale,
		up:   true,
		build: func() (Executor, error) {
			return fresh, nil
		},
		lastUsed: time.Now().Add(-time.Hour),
	}
	p := newDirectPoolReap(c, fakeClassifier{}, 30*time.Second)

	p.reapIdle(time.Now())

	res, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
	if err != nil {
		t.Fatalf("Run after reap: %v", err)
	}
	if res.Stdout != "ok" {
		t.Errorf("Stdout = %q, want %q (from the rebuilt client)", res.Stdout, "ok")
	}
	fresh.mu.Lock()
	gotConnects := fresh.connects
	fresh.mu.Unlock()
	if gotConnects != 1 {
		t.Errorf("fresh.connects = %d, want 1 (must reconnect lazily after a reap)", gotConnects)
	}
	stale.mu.Lock()
	gotExecutes := stale.executes
	stale.mu.Unlock()
	if gotExecutes != 0 {
		t.Errorf("stale.executes = %d, want 0 (the reaped client must never be used again)", gotExecutes)
	}
}

// TestReapLeavesRecentlyUsedConnAlone: a conn used within the ReapAfter
// window must not be reaped — closing a shell still in active rotation would
// be a functional regression, not a fix.
func TestReapLeavesRecentlyUsedConnAlone(t *testing.T) {
	f := &fakeExec{result: adpwsh.Result{}}
	built := 0
	c := &conn{
		exec: f,
		up:   true,
		build: func() (Executor, error) {
			built++
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
		lastUsed: time.Now(),
	}
	p := newDirectPoolReap(c, fakeClassifier{}, 30*time.Second)

	p.reapIdle(time.Now())

	f.mu.Lock()
	gotCloses := f.closes
	f.mu.Unlock()
	if gotCloses != 0 {
		t.Errorf("closes = %d, want 0 (conn used within the window must not be reaped)", gotCloses)
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
	f := &fakeExec{result: adpwsh.Result{}}
	built := 0
	c := &conn{
		exec: f,
		up:   false,
		build: func() (Executor, error) {
			built++
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
		lastUsed: time.Now().Add(-time.Hour), // stale, but irrelevant: never connected
	}
	p := newDirectPoolReap(c, fakeClassifier{}, 30*time.Second)

	p.reapIdle(time.Now())

	f.mu.Lock()
	gotCloses := f.closes
	f.mu.Unlock()
	if gotCloses != 0 {
		t.Errorf("closes = %d, want 0 (never connected, nothing live to close)", gotCloses)
	}
	if built != 0 {
		t.Errorf("build calls = %d, want 0 (no spurious rebuild of an already-fresh conn)", built)
	}
	c.mu.Lock()
	gotExec := c.exec
	c.mu.Unlock()
	if gotExec != Executor(f) {
		t.Error("c.exec was replaced even though the conn was never connected")
	}
}

// newRealTestPool builds a Pool through the real New(), the only path that
// starts the reap goroutine — every other test in this file builds a Pool by
// struct literal specifically to avoid that goroutine, so the New/Close
// lifecycle gets its own real construction here. The Build closure does no
// network I/O, so this is safe and fast to call in a unit test.
func newRealTestPool(t *testing.T, concurrency int, reapAfter time.Duration) *Pool {
	t.Helper()
	p, err := New(Params{
		Concurrency: concurrency,
		Timeout:     2 * time.Second,
		ReapAfter:   reapAfter,
		Build: func() (Executor, error) {
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
		Wrapper:    identityWrapper,
		Classifier: fakeClassifier{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestCloseStopsReapLoop: Close must not return until the reap goroutine has
// actually exited — asserted via reapDone closing, not assumed from Close
// merely returning without error. A goroutine that outlives Close is a leak:
// nothing else in this process will ever stop it.
func TestCloseStopsReapLoop(t *testing.T) {
	p := newRealTestPool(t, 1, time.Hour)

	select {
	case <-p.reapDone:
		t.Fatal("reapDone already closed before Close was ever called")
	default:
		// Expected: the loop is running.
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-p.reapDone:
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
		p := newRealTestPool(t, 2, time.Hour)
		if err := p.Close(); err != nil {
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
// the reaper into a busy-loop.
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

// newStressTestPool builds a Pool the same way New() does — reapStop/reapDone
// wired, reapLoop actually started — but with fakeExec clients instead of
// real ones, so it can be driven concurrently at speed. It exists
// specifically for TestReapAndRunUnderConcurrentStress: every other test in
// this file that starts the real goroutine (newRealTestPool) creates and
// immediately Closes without ever calling Run, so nothing before this test
// actually overlaps the reaper with an in-flight Run in time — every
// reap-behavior test above calls reapIdle synchronously and sequentially
// with Run, never concurrently.
func newStressTestPool(params Params) *Pool {
	build := func() (Executor, error) { return &fakeExec{result: adpwsh.Result{}}, nil }
	params.Build = build
	p := &Pool{
		params:   params,
		idle:     make(chan *conn, params.Concurrency),
		reapStop: make(chan struct{}),
		reapDone: make(chan struct{}),
	}
	for i := 0; i < params.Concurrency; i++ {
		// Mirrors New()'s own construction: every conn needs a non-nil exec
		// from the start (up stays false, so it connects lazily on first
		// use, exactly like a real pool) — a conn built with a nil exec is
		// not a state Run or the reaper is ever meant to encounter.
		c, err := build()
		if err != nil {
			panic(err) // build() above never errors; a test-only invariant
		}
		p.idle <- &conn{exec: c, build: build}
	}
	go p.reapLoop()
	return p
}

// TestReapAndRunUnderConcurrentStress drives Run and the real reap goroutine
// against each other for real wall-clock time, then Closes — the gap every
// other test in this file leaves open: they either call reapIdle
// synchronously and sequentially with Run (never overlapping in time), or
// start the real goroutine and Close immediately without issuing any Runs.
// The properties argued for in reapIdle/reapConnIfIdle/Close's own comments
// — that the reaper can never observe a conn a Run holds, can never block a
// Run, and that Close cannot race a sweep in flight — are checked here under
// actual concurrent scheduling, not only by inspection. -race is what makes
// this test meaningful: it cannot catch a defect in an interaction no test
// actually drives concurrently.
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
	p := newStressTestPool(Params{
		Concurrency: concurrency,
		Timeout:     2 * time.Second,
		ReapAfter:   30 * time.Millisecond,
		Wrapper:     identityWrapper,
		Classifier:  fakeClassifier{},
	})

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
				_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
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
		case c := <-p.idle:
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
	case c := <-p.idle:
		t.Fatalf("pool has more than %d conns after the stress run (extra: %p)", concurrency, c)
	default:
		// Expected: exactly `concurrency` conns total, no extras conjured
		// and none lost.
	}
	for _, c := range drained {
		p.idle <- c // restore before Close, which itself expects to drain exactly Concurrency conns
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5s (reaper likely failed to stop, or deadlocked against the drain)")
	}
}

// TestConcurrentPoolWideReapRecovers models a WinRM bounce that kills every
// shell in the pool at once — not just one conn among several healthy ones.
// Several conns are all dead simultaneously; concurrent Runs across them must
// each independently invalidate and rebuild without racing on shared state.
// All conns share a SINGLE build closure, exactly as New() wires it in
// production (one closure over Params, reused for every pooled conn) — a
// separate closure literal per conn would not exercise concurrent entry into
// one shared build. Run with -race: this exercises this package's own
// locking (each conn's own mutex, the Pool's idle channel, and the shared
// build closure's own atomic counter) under real concurrency.
func TestConcurrentPoolWideReapRecovers(t *testing.T) {
	const n = 4
	var builds int32
	dead := errors.New("shell gone")
	build := func() (Executor, error) {
		atomic.AddInt32(&builds, 1)
		return &fakeExec{result: adpwsh.Result{}}, nil
	}

	cl := fakeClassifier{
		kind:      map[error]adpwsh.Kind{dead: adpwsh.KindTransport},
		deadShell: map[error]bool{dead: true},
	}

	p := &Pool{
		params: Params{
			Classifier:  cl,
			Wrapper:     identityWrapper,
			Timeout:     2 * time.Second,
			Concurrency: n,
		},
		idle: make(chan *conn, n),
	}
	for i := 0; i < n; i++ {
		p.idle <- &conn{
			exec:  &fakeExec{execErr: dead},
			up:    true, // every shell in the pool believes itself connected
			build: build,
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Run failed: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&builds); got != n {
		t.Errorf("builds = %d, want %d (one rebuild per dead conn, through the shared closure)", got, n)
	}
}
