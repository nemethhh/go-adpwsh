package warm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// newTestPool builds a Concurrency-sized pool (via New) whose Build hands out
// execs round-robin (execs[i % len(execs)]) in the order it is called. It is
// used only by tests that do not need to observe rebuild counts directly; the
// invalidate/retry tests below construct their *conn/*Pool by hand instead
// (mirroring transport/psrp/psrp_test.go), since invalidate() drops the dead
// executor and rebuilds via conn.build rather than closing it — closes is not
// how a rebuild is observed.
func newTestPool(t *testing.T, execs []*fakeExec, cl Classifier) *Pool {
	t.Helper()
	i := 0
	var mu sync.Mutex
	p, err := New(Params{
		Concurrency: len(execs),
		Timeout:     2 * time.Second,
		ReapAfter:   time.Hour, // effectively disable the reaper for these tests
		Build: func() (Executor, error) {
			mu.Lock()
			e := execs[i%len(execs)]
			i++
			mu.Unlock()
			return e, nil
		},
		Wrapper:    identityWrapper,
		Classifier: cl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// newDirectPool builds a *Pool around a single hand-built *conn, bypassing
// New entirely (no background goroutine is started, so there is nothing to
// Close). This mirrors psrp_test.go's pattern of constructing &Transport{cfg,
// idle} directly so a test can supply its own build closure and inspect
// exactly how many times it was called.
func newDirectPool(c *conn, cl Classifier) *Pool {
	p := &Pool{
		params: Params{
			Classifier:  cl,
			Wrapper:     identityWrapper,
			Timeout:     2 * time.Second,
			Concurrency: 1,
		},
		idle: make(chan *conn, 1),
	}
	p.idle <- c
	return p
}

func mustEncode(t *testing.T, script string) string {
	t.Helper()
	return adscript.EncodeCommand(script)
}

// mirrors TestRunReassemblesOutput / TestRunHadErrorsExitCode (psrp_test.go):
// the pool returns the executor's adpwsh.Result verbatim.
func TestRunReturnsExecutorResult(t *testing.T) {
	e := &fakeExec{result: adpwsh.Result{Stdout: "ok", ExitCode: 0}}
	p := newTestPool(t, []*fakeExec{e}, fakeClassifier{})
	res, err := p.Run(context.Background(), mustEncode(t, "Get-Foo"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != "ok" {
		t.Fatalf("Stdout = %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
	}
}

// mirrors TestRunExecuteErrorIsTransport (psrp_test.go): a generic
// (non-transient, non-deadshell) Execute error surfaces as KindTransport via
// the classifier.
func TestRunExecuteErrorIsTransport(t *testing.T) {
	e := &fakeExec{execErr: errors.New("dial tcp: connection refused")}
	p := newTestPool(t, []*fakeExec{e}, fakeClassifier{})
	_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
	var ae *adpwsh.Error
	if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransport {
		t.Errorf("want KindTransport, got %v", err)
	}
}

// mirrors TestPoolCheckoutSpreadsAcrossClients (psrp_test.go): with a 2-conn
// pool and 2 concurrent Runs, both conns are used (no single conn serves
// both). The two Runs are gated inside Execute so this only passes if both
// conns are genuinely checked out at the same time, not merely serialized.
func TestPoolCheckoutSpreadsAcrossClients(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	e1 := &fakeExec{result: adpwsh.Result{}, arrived: arrived, release: release}
	e2 := &fakeExec{result: adpwsh.Result{}, arrived: arrived, release: release}
	p := newTestPool(t, []*fakeExec{e1, e2}, fakeClassifier{})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Run(context.Background(), mustEncode(t, "x"), nil)
		}()
	}

	// Both goroutines must be inside Execute simultaneously for this to
	// receive twice: with only one conn available, the second Run would
	// block on checkout and never reach Execute to send here.
	<-arrived
	<-arrived
	close(release)
	wg.Wait()

	if e1.executes != 1 || e2.executes != 1 {
		t.Errorf("expected each conn used exactly once, got e1=%d e2=%d", e1.executes, e2.executes)
	}
}

// mirrors TestRunTransientFailureDoesNotInvalidateConn (psrp_test.go): a
// KindTransient classification means the shell is fine and nothing was even
// attempted. Run must not rebuild the conn (built==0) or retry (executes==1).
func TestRunTransientDoesNotInvalidate(t *testing.T) {
	transient := errors.New("busy")
	e := &fakeExec{execErr: transient}
	built := 0
	c := &conn{
		exec: e,
		up:   true, // already connected; a real warm shell
		build: func() (Executor, error) {
			built++
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
	}
	cl := fakeClassifier{kind: map[error]adpwsh.Kind{transient: adpwsh.KindTransient}}
	p := newDirectPool(c, cl)

	_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
	var ae *adpwsh.Error
	if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransient {
		t.Fatalf("want KindTransient, got %v", err)
	}
	if built != 0 {
		t.Fatalf("build calls = %d, want 0 (a transient failure must not rebuild a good shell)", built)
	}
	if e.executes != 1 {
		t.Fatalf("Execute calls = %d, want 1 (no retry for a transient failure)", e.executes)
	}
}

// mirrors TestRunContextErrorDoesNotInvalidateOrRetry (psrp_test.go): a
// context deadline or cancellation from Execute maps KindTransport (not
// retryable by core.exec) but must not invalidate the conn (built==0) — the
// caller gave up, the shell is probably still fine.
func TestRunContextErrorDoesNotInvalidateOrRetry(t *testing.T) {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		e := &fakeExec{execErr: ctxErr}
		built := 0
		c := &conn{
			exec: e,
			up:   true,
			build: func() (Executor, error) {
				built++
				return &fakeExec{result: adpwsh.Result{}}, nil
			},
		}
		cl := fakeClassifier{kind: map[error]adpwsh.Kind{ctxErr: adpwsh.KindTransport}}
		p := newDirectPool(c, cl)

		_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
		var ae *adpwsh.Error
		if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransport {
			t.Fatalf("%v: want KindTransport, got %v", ctxErr, err)
		}
		if built != 0 {
			t.Errorf("%v: build calls = %d, want 0 (a context error must not be treated as evidence the shell is dead)", ctxErr, built)
		}
		if e.executes != 1 {
			t.Errorf("%v: Execute calls = %d, want 1 (a context error must never be retried)", ctxErr, e.executes)
		}
	}
}

// mirrors TestRunAmbiguousTransportFailureDoesNotRetry (psrp_test.go): a
// KindTransport failure that is not a confirmed dead-shell signature must not
// be retried within this Run (executes==1) — the script may already have
// reached AD. The conn is still rebuilt (built==1) so a LATER, unrelated Run
// does not inherit a permanently poisoned client.
func TestRunAmbiguousDoesNotRetry(t *testing.T) {
	ambiguous := errors.New("maybe executed")
	e := &fakeExec{execErr: ambiguous}
	built := 0
	c := &conn{
		exec: e,
		up:   true,
		build: func() (Executor, error) {
			built++
			return &fakeExec{result: adpwsh.Result{}}, nil
		},
	}
	cl := fakeClassifier{
		kind:      map[error]adpwsh.Kind{ambiguous: adpwsh.KindTransport},
		deadShell: map[error]bool{ambiguous: false},
	}
	p := newDirectPool(c, cl)

	_, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
	if err == nil {
		t.Fatal("want error")
	}
	if built != 1 {
		t.Fatalf("build calls = %d, want 1 (conn still fixed for next time)", built)
	}
	if e.executes != 1 {
		t.Fatalf("ambiguous must not retry; executes=%d", e.executes)
	}
}

// mirrors TestRunRecoversFromDeadShellWithOneTransparentRetry (psrp_test.go):
// a confirmed dead-shell (pipeline-start) failure invalidates the conn
// (built==1) and transparently retries exactly once against the freshly
// rebuilt executor.
func TestRunDeadShellRetriesExactlyOnce(t *testing.T) {
	dead := errors.New("shell gone")
	first := &fakeExec{execErr: dead}
	second := &fakeExec{result: adpwsh.Result{Stdout: "recovered"}}
	built := 0
	c := &conn{
		exec: first,
		up:   true, // first's underlying shell still believes itself connected
		build: func() (Executor, error) {
			built++
			return second, nil
		},
	}
	cl := fakeClassifier{
		kind:      map[error]adpwsh.Kind{dead: adpwsh.KindTransport},
		deadShell: map[error]bool{dead: true},
	}
	p := newDirectPool(c, cl)

	res, err := p.Run(context.Background(), mustEncode(t, "x"), nil)
	if err != nil {
		t.Fatalf("Run: %v, want transparent recovery", err)
	}
	if res.Stdout != "recovered" {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, "recovered")
	}
	if built != 1 {
		t.Fatalf("build calls = %d, want exactly 1", built)
	}
	if first.executes != 1 {
		t.Fatalf("first.executes = %d, want 1 (must not retry the same dead exec)", first.executes)
	}
	if second.executes != 1 {
		t.Fatalf("second.executes = %d, want 1", second.executes)
	}
	if second.connects != 1 {
		t.Fatalf("second.connects = %d, want 1 (the rebuilt exec must actually connect)", second.connects)
	}
}

// mirrors TestRunGivesUpAfterExactlyOneRetry (psrp_test.go): if the rebuilt
// executor is also dead, Run must surface the error rather than loop — the
// retry budget is exactly one (built==1), never a retry-until-success loop.
func TestRunGivesUpAfterExactlyOneRetry(t *testing.T) {
	dead := errors.New("shell gone")
	first := &fakeExec{execErr: dead}
	second := &fakeExec{execErr: dead}
	built := 0
	c := &conn{
		exec: first,
		up:   true,
		build: func() (Executor, error) {
			built++
			return second, nil
		},
	}
	cl := fakeClassifier{
		kind:      map[error]adpwsh.Kind{dead: adpwsh.KindTransport},
		deadShell: map[error]bool{dead: true},
	}
	p := newDirectPool(c, cl)

	if _, err := p.Run(context.Background(), mustEncode(t, "x"), nil); err == nil {
		t.Fatal("want error: both the original and the rebuilt exec are dead")
	}
	if built != 1 {
		t.Fatalf("build calls = %d, want exactly 1 (no retry loop)", built)
	}
	if first.executes != 1 || second.executes != 1 {
		t.Fatalf("first.executes=%d second.executes=%d, want 1 and 1 (exactly one retry, never a loop)", first.executes, second.executes)
	}
}
