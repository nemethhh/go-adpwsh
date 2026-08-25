package psrp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
)

type fakeExec struct {
	mu           sync.Mutex
	calls        int
	connectCalls int
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
func (f *fakeExec) Close(context.Context) error { return nil }
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
func newTestTransport(fakes ...*fakeExec) *Transport {
	cfg := Config{Host: "dc"}.WithDefaults()
	cfg.Concurrency = len(fakes)
	t := &Transport{cfg: cfg, idle: make(chan *conn, len(fakes))}
	for _, f := range fakes {
		t.idle <- &conn{exec: f, up: true}
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

// TestRunTransportFailureInvalidatesConn: a transport-class Execute failure
// (KindTransport — dial/auth/protocol, not a busy queue or a deadline) means
// the shell itself is suspect, so the conn must be marked not-connected. The
// next Run through it reconnects instead of reusing a dead shell — without
// this, every later Run on that pooled conn would fail for the life of the
// process (finding 3 in the leak analysis).
func TestRunTransportFailureInvalidatesConn(t *testing.T) {
	f := &fakeExec{execErr: errors.New("dial tcp: connection refused")}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- &conn{exec: f} // up defaults false, same as a freshly built pool

	if _, err := tr.Run(context.Background(), encode("x"), nil); err == nil {
		t.Fatal("first Run: want error, got nil")
	}
	if f.connectCalls != 1 {
		t.Fatalf("connectCalls after first Run = %d, want 1", f.connectCalls)
	}

	f.mu.Lock()
	f.execErr = nil
	f.result = &psrp.Result{}
	f.mu.Unlock()

	if _, err := tr.Run(context.Background(), encode("x"), nil); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if f.connectCalls != 2 {
		t.Errorf("connectCalls after second Run = %d, want 2 (dead shell should have been reconnected)", f.connectCalls)
	}
}

// TestRunTransientFailureDoesNotInvalidateConn: a context deadline (or other
// KindTransient condition) does not mean the shell is dead. Tearing down a
// warm shell over one operation's deadline would be a performance regression
// — the transport should reuse it, not reconnect.
func TestRunTransientFailureDoesNotInvalidateConn(t *testing.T) {
	f := &fakeExec{execErr: context.DeadlineExceeded}
	tr := &Transport{cfg: Config{Host: "dc"}.WithDefaults(), idle: make(chan *conn, 1)}
	tr.idle <- &conn{exec: f, up: true} // already connected; a real warm shell

	_, err := tr.Run(context.Background(), encode("x"), nil)
	var e *adpwsh.Error
	if !errors.As(err, &e) || e.Kind != adpwsh.KindTransient {
		t.Fatalf("first Run: want KindTransient, got %v", err)
	}

	f.mu.Lock()
	f.execErr = nil
	f.result = &psrp.Result{}
	f.mu.Unlock()

	if _, err := tr.Run(context.Background(), encode("x"), nil); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if f.connectCalls != 0 {
		t.Errorf("connectCalls = %d, want 0 (a transient failure must not invalidate a good shell)", f.connectCalls)
	}
}
