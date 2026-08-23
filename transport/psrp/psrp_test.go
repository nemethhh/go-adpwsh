package psrp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
)

type fakeExec struct {
	mu         sync.Mutex
	calls      int
	lastScript string
	result     *psrp.Result
	execErr    error

	// arrived/release, when non-nil, let a test gate concurrency: Execute
	// signals arrival then blocks until release is closed/sent to.
	arrived chan struct{}
	release chan struct{}
}

func (f *fakeExec) Connect(context.Context) error { return nil }
func (f *fakeExec) Close(context.Context) error   { return nil }
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
