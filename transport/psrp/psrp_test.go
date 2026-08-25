package psrp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
)

type fakeExec struct {
	mu           sync.Mutex
	calls        int
	connectCalls int
	closeCalls   int
	closeErr     error
	lastScript   string
	result       *psrp.Result
	execErr      error

	// arrived/release, when non-nil, let a test gate concurrency: Execute
	// signals arrival then blocks until release is closed/sent to.
	arrived chan struct{}
	release chan struct{}
}

func (f *fakeExec) Connect(context.Context) error {
	f.mu.Lock()
	f.connectCalls++
	f.mu.Unlock()
	return nil
}
func (f *fakeExec) Close(context.Context) error {
	f.mu.Lock()
	f.closeCalls++
	err := f.closeErr
	f.mu.Unlock()
	return err
}
func (f *fakeExec) Execute(_ context.Context, s string) (*psrp.Result, error) {
	f.mu.Lock()
	f.calls++
	f.lastScript = s
	f.mu.Unlock()
	if f.arrived != nil {
		f.arrived <- struct{}{}
		<-f.release
	}
	return f.result, f.execErr
}

// newTestTransport builds a pool from the given fakes (already "connected").
// Each conn gets a default build closure that hands back a fresh, healthy
// fakeExec if invalidate ever rebuilds it — tests that care about exactly
// what gets rebuilt construct their own conn (and their own build) directly,
// as the retry/invalidate tests below do.
func newTestTransport(fakes ...*fakeExec) *Transport {
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.Concurrency = len(fakes)
	t := &Transport{cfg: cfg, idle: make(chan *conn, len(fakes))}
	for _, f := range fakes {
		t.idle <- &conn{
			exec: f,
			up:   true,
			build: func() (executor, error) {
				return &fakeExec{result: &psrp.Result{}}, nil
			},
		}
	}
	return t
}

func TestRunReassemblesOutput(t *testing.T) {
	f := &fakeExec{result: &psrp.Result{
		Output:    []interface{}{"<<<TFAD:BEGIN>>>", `{"ok":true}`, "<<<TFAD:END>>>"},
		HadErrors: false,
	}}
	tr := newTestTransport(f)

	res, err := tr.Run(context.Background(), encode("Get-ADDomain"), []byte(`{"server":null}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	want := "<<<TFAD:BEGIN>>>\n{\"ok\":true}\n<<<TFAD:END>>>"
	if res.Stdout != want {
		t.Errorf("Stdout = %q, want %q", res.Stdout, want)
	}
	if !strings.Contains(f.lastScript, "Get-ADDomain") || !strings.Contains(f.lastScript, "SetIn") {
		t.Errorf("executor got unexpected script: %q", f.lastScript)
	}
}

func TestRunHadErrorsExitCode(t *testing.T) {
	f := &fakeExec{result: &psrp.Result{Output: []interface{}{"boom"}, Errors: []interface{}{"err1"}, HadErrors: true}}
	res, err := newTestTransport(f).Run(context.Background(), encode("x"), nil)
	if err != nil {
		t.Fatalf("Run returned transport error for an AD-level failure: %v", err)
	}
	if res.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", res.ExitCode)
	}
	if res.Stderr != "err1" {
		t.Errorf("Stderr = %q, want err1", res.Stderr)
	}
}

func TestRunExecuteErrorIsTransport(t *testing.T) {
	f := &fakeExec{execErr: errors.New("dial tcp: connection refused")}
	_, err := newTestTransport(f).Run(context.Background(), encode("x"), nil)
	var e *adpwsh.Error
	if !errors.As(err, &e) || e.Kind != adpwsh.KindTransport {
		t.Errorf("want KindTransport, got %v", err)
	}
}

// TestPoolCheckoutSpreadsAcrossClients: with a 2-client pool and 2 concurrent
// Runs, both clients are used (no single client serves both). The two Runs
// are gated inside Execute so this only passes if both conns are genuinely
// checked out at the same time, not merely round-robined sequentially.
func TestPoolCheckoutSpreadsAcrossClients(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	f1 := &fakeExec{result: &psrp.Result{}, arrived: arrived, release: release}
	f2 := &fakeExec{result: &psrp.Result{}, arrived: arrived, release: release}
	tr := newTestTransport(f1, f2)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = tr.Run(context.Background(), encode("x"), nil) }()
	}

	// Both goroutines must be inside Execute simultaneously for this to
	// receive twice: with only one conn available, the second Run would
	// block on checkout and never reach Execute to send here.
	<-arrived
	<-arrived
	close(release)
	wg.Wait()

	if f1.calls != 1 || f2.calls != 1 {
		t.Errorf("expected each client used exactly once, got f1=%d f2=%d", f1.calls, f2.calls)
	}
}

// TestBuildPSRPConfigIdleTimeoutDefault: newClient's go-psrp config must carry
// a short, non-empty IdleTimeout. Left unset, go-psrp itself requests a
// 30-minute shell lease (PT30M) — the root cause of the WinRM-shell leak this
// change closes — so this must never come back empty.
func TestBuildPSRPConfigIdleTimeoutDefault(t *testing.T) {
	cfg := Config{Host: "dc"}.WithDefaults()
	pc := buildPSRPConfig(cfg)
	if pc.IdleTimeout == "" {
		t.Fatal("IdleTimeout is empty; go-psrp will fall back to its own PT30M default")
	}
	if pc.IdleTimeout != "PT120S" {
		t.Errorf("IdleTimeout = %q, want PT120S (2 minutes)", pc.IdleTimeout)
	}
}

// TestBuildPSRPConfigIdleTimeoutExplicit: an explicit Config.IdleTimeout is
// translated verbatim into the ISO8601 form go-psrp expects.
func TestBuildPSRPConfigIdleTimeoutExplicit(t *testing.T) {
	cfg := Config{Host: "dc", IdleTimeout: 5 * time.Minute}.WithDefaults()
	pc := buildPSRPConfig(cfg)
	if pc.IdleTimeout != "PT300S" {
		t.Errorf("IdleTimeout = %q, want PT300S (5 minutes)", pc.IdleTimeout)
	}
}

// TestBuildPSRPConfigLeavesGoPSRPRetryMachineryOff: our own Run does exactly
// one bounded, narrowly-scoped retry (see isDeadShellFailure). Nothing
// enforces that go-psrp's own retry machinery stays out of the way — if
// Config.Retry or Config.Reconnect were ever enabled (by us, or by a future
// go-psrp default change), its retries would compound with ours and
// reintroduce the double-execution risk this transport is built to avoid.
// buildPSRPConfig never touches either field, so psrp.DefaultConfig()'s own
// defaults (Retry: nil, Reconnect.Enabled: false) must survive untouched.
func TestBuildPSRPConfigLeavesGoPSRPRetryMachineryOff(t *testing.T) {
	pc := buildPSRPConfig(Config{Host: "dc"}.WithDefaults())
	if pc.Retry != nil {
		t.Errorf("Retry = %+v, want nil (go-psrp's own command retry must stay disabled)", pc.Retry)
	}
	if pc.Reconnect.Enabled {
		t.Error("Reconnect.Enabled = true, want false (go-psrp's own reconnect policy must stay disabled)")
	}
}

// TestRunTransientFailureDoesNotInvalidateConn: a genuinely transient,
// provably-pre-send condition (one of the three go-psrp sentinels
// mapExecuteError recognizes) does not mean the shell is dead. Run must not
// rebuild the conn or retry — the shell is fine, and the caller (or
// core.exec, one layer up) will simply try again later.
//
// This deliberately does NOT use a context error as its fixture, even
// though a context error also does not invalidate the conn (see
// TestRunContextErrorDoesNotInvalidateOrRetry below). context.Canceled and
// context.DeadlineExceeded map to KindTransport, not KindTransient (see
// wrap.go's mapExecuteError) — a context-error fixture here would assert the
// wrong Kind. The two "conn left alone" outcomes reach the same conclusion
// for different reasons — one because nothing was ever attempted, the other
// because Run treats a shell of unknown-but-probably-fine status as not
// worth discarding (isCallerTimeout) — so they stay two tests rather than
// one that would misstate either reason.
func TestRunTransientFailureDoesNotInvalidateConn(t *testing.T) {
	f := &fakeExec{execErr: psrp.ErrQueueFull}
	built := 0
	c := &conn{
		exec: f,
		up:   true, // already connected; a real warm shell
		build: func() (executor, error) {
			built++
			return &fakeExec{result: &psrp.Result{}}, nil
		},
	}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- c

	_, err := tr.Run(context.Background(), encode("x"), nil)
	var e *adpwsh.Error
	if !errors.As(err, &e) || e.Kind != adpwsh.KindTransient {
		t.Fatalf("want KindTransient, got %v", err)
	}
	if built != 0 {
		t.Errorf("build calls = %d, want 0 (a transient failure must not rebuild a good shell)", built)
	}
	if f.calls != 1 {
		t.Errorf("Execute calls = %d, want 1 (no retry for a transient failure)", f.calls)
	}
}

// TestRunContextErrorDoesNotInvalidateOrRetry pins the follow-up refinement
// to the retry-safety fix: a context deadline or cancellation from Execute
// is not one of the three provably-pre-send sentinels, so mapExecuteError
// classifies it KindTransport (see wrap.go) and core.exec will never retry
// it — but that answers only "is it safe to retry?", not "is the shell
// dead?". isCallerTimeout answers the second question separately, and Run
// must NOT invalidate the conn here: the caller gave up, the shell is
// probably still fine, and discarding a good client on every timeout would
// leak it for up to Config.IdleTimeout (the abandoned client is never
// closed by this package, only left to expire on its own lease) — undoing
// the shell-leak fix and charging the next Run on this conn a fresh
// AD-module import (~366ms) it didn't need to pay.
//
// An earlier version of this test asserted the conn WAS rebuilt on a
// context error. That was the bug this refinement closes — do not revert
// the "built == 0" assertion below back to expecting a rebuild.
func TestRunContextErrorDoesNotInvalidateOrRetry(t *testing.T) {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		f := &fakeExec{execErr: ctxErr}
		built := 0
		c := &conn{
			exec: f,
			up:   true,
			build: func() (executor, error) {
				built++
				return &fakeExec{result: &psrp.Result{}}, nil
			},
		}
		tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
		tr.idle <- c

		_, err := tr.Run(context.Background(), encode("x"), nil)
		var e *adpwsh.Error
		if !errors.As(err, &e) || e.Kind != adpwsh.KindTransport {
			t.Fatalf("%v: want KindTransport, got %v", ctxErr, err)
		}
		if built != 0 {
			t.Errorf("%v: build calls = %d, want 0 (a context error must not be treated as evidence the shell is dead)", ctxErr, built)
		}
		if f.calls != 1 {
			t.Errorf("%v: Execute calls = %d, want 1 (a context error must never be retried, here or in core.exec)", ctxErr, f.calls)
		}
	}
}

// TestRunAmbiguousTransportFailureDoesNotRetry: a KindTransport failure that
// is not one of the confirmed pipeline-start signatures (isDeadShellFailure)
// must not be retried within this Run — the script may already have reached
// Active Directory. The conn is still rebuilt so a LATER, unrelated Run does
// not inherit a permanently poisoned client (the general fix for finding 3).
func TestRunAmbiguousTransportFailureDoesNotRetry(t *testing.T) {
	// "read output stream: unexpected EOF" models a failure surfacing after a
	// pipeline was already invoked (e.g. pipeline.Wait(), reached only once
	// the script may have started running) — not one of the pipeline-start
	// prefixes this transport recognizes as safe to retry.
	f := &fakeExec{execErr: errors.New("read output stream: unexpected EOF")}
	built := 0
	c := &conn{
		exec: f,
		up:   true,
		build: func() (executor, error) {
			built++
			return &fakeExec{result: &psrp.Result{}}, nil
		},
	}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- c

	_, err := tr.Run(context.Background(), encode("x"), nil)
	var e *adpwsh.Error
	if !errors.As(err, &e) || e.Kind != adpwsh.KindTransport {
		t.Fatalf("want KindTransport surfaced, got %v", err)
	}
	if built != 1 {
		t.Errorf("build calls = %d, want 1 (conn still fixed for next time)", built)
	}
	if f.calls != 1 {
		t.Errorf("Execute calls = %d, want 1 (must not retry an ambiguous failure)", f.calls)
	}
}

// TestRunRecoversFromDeadShellWithOneTransparentRetry is the core defect this
// round closes. dead models exactly what the lab found: go-psrp's own Client
// keeps believing it is connected after its shell is reaped — Connect
// trivially succeeds (fakeExec.Connect always does), while Execute keeps
// failing the way a dead pipeline-start does. Simply flagging the conn and
// reconnecting the SAME object cannot recover from that (Connect on a client
// that still thinks it's connected is a no-op) — Run must discard dead and
// swap in a genuinely fresh client (alive) via conn.build, then retry the
// same operation once, transparently, so the caller sees success.
func TestRunRecoversFromDeadShellWithOneTransparentRetry(t *testing.T) {
	dead := &fakeExec{execErr: errors.New("failed to start pipeline after retries due to transport error")}
	alive := &fakeExec{result: &psrp.Result{Output: []interface{}{"ok"}}}

	built := 0
	c := &conn{
		exec: dead,
		up:   true, // dead's underlying Client still believes itself connected
		build: func() (executor, error) {
			built++
			return alive, nil
		},
	}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- c

	res, err := tr.Run(context.Background(), encode("x"), nil)
	if err != nil {
		t.Fatalf("Run: %v, want transparent recovery", err)
	}
	if res.Stdout != "ok" {
		t.Errorf("Stdout = %q, want %q (from the rebuilt client)", res.Stdout, "ok")
	}
	if built != 1 {
		t.Errorf("build calls = %d, want exactly 1", built)
	}
	if dead.calls != 1 {
		t.Errorf("dead.calls = %d, want 1 (must not retry the same dead client)", dead.calls)
	}
	if alive.calls != 1 {
		t.Errorf("alive.calls = %d, want 1", alive.calls)
	}
	if alive.connectCalls != 1 {
		t.Errorf("alive.connectCalls = %d, want 1 (the rebuilt client must actually connect)", alive.connectCalls)
	}
}

// TestRunGivesUpAfterExactlyOneRetry: if the rebuilt client is also dead, Run
// must surface the error rather than loop — the retry budget is exactly one,
// never a retry-until-success loop.
func TestRunGivesUpAfterExactlyOneRetry(t *testing.T) {
	dead1 := &fakeExec{execErr: errors.New("failed to start pipeline after retries due to transport error")}
	dead2 := &fakeExec{execErr: errors.New("failed to start pipeline after retries due to transport error")}

	built := 0
	c := &conn{
		exec: dead1,
		up:   true,
		build: func() (executor, error) {
			built++
			return dead2, nil
		},
	}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- c

	if _, err := tr.Run(context.Background(), encode("x"), nil); err == nil {
		t.Fatal("want error: both the original and the rebuilt client are dead")
	}
	if built != 1 {
		t.Errorf("build calls = %d, want exactly 1 (no retry loop)", built)
	}
	if dead1.calls != 1 || dead2.calls != 1 {
		t.Errorf("dead1.calls=%d dead2.calls=%d, want 1 and 1 (exactly one retry, never a loop)", dead1.calls, dead2.calls)
	}
}

// TestConcurrentPoolWideReapRecovers models a WinRM bounce that kills every
// shell in the pool at once — not just one conn among several healthy ones.
// Several conns are all dead simultaneously; concurrent Runs across them must
// each independently invalidate and rebuild without racing on shared state.
// All conns share a SINGLE build closure, exactly as New() wires it in
// production (one closure over cfg, reused for every pooled conn) — a
// separate closure literal per conn would not exercise concurrent entry into
// one shared build. Run with -race: this exercises this package's own
// locking (each conn's own mutex, the Transport's idle channel, and the
// shared build closure's own atomic counter) under real concurrency. It
// cannot exercise reentrancy in go-psrp's own Kerberos-provider construction
// when several real psrp.New calls race in a real process — that is a
// residual outside what a fake-backed unit test can cover.
func TestConcurrentPoolWideReapRecovers(t *testing.T) {
	const n = 4
	var builds int32
	build := func() (executor, error) {
		atomic.AddInt32(&builds, 1)
		return &fakeExec{result: &psrp.Result{}}, nil
	}

	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, n)}
	for i := 0; i < n; i++ {
		dead := &fakeExec{execErr: errors.New(deadShellRetryExhaustedMessage)}
		tr.idle <- &conn{
			exec:  dead,
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
			_, err := tr.Run(context.Background(), encode("x"), nil)
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
