package local_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	adlocal "github.com/nemethhh/go-adpwsh/transport/local"
)

// newTransport builds a transport pointed at the compiled stub and closes it
// when the test ends.
func newTransport(t *testing.T, cfg adlocal.Config) *adlocal.Transport {
	t.Helper()
	if cfg.PwshPath == "" {
		cfg.PwshPath = stubPath
	}
	tr, err := adlocal.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// The command must be the exact invocation the Transport contract documents,
// and the payload must arrive on stdin rather than on the command line: a
// password on argv is visible in the host's process table.
func TestLocalRunsTheDocumentedCommandWithPayloadOnStdin(t *testing.T) {
	records := recordFile(t)
	t.Setenv("PWSHSTUB_STDOUT", "<<<TFAD:BEGIN>>>\r\n{\"ok\":true,\"data\":{}}\r\n<<<TFAD:END>>>\r\n")

	tr := newTransport(t, adlocal.Config{})
	res, err := tr.Run(context.Background(), "QQBCAA==", []byte(`{"op":"rootdse"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "TFAD:BEGIN") {
		t.Errorf("result = %+v", res)
	}

	recs := stubRecords(t, records)
	if len(recs) == 0 {
		t.Fatal("the stub recorded nothing; Run did not start it")
	}
	want := []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", "QQBCAA=="}
	if !slices.Equal(recs[0].Args, want) {
		t.Errorf("args = %q, want %q", recs[0].Args, want)
	}
	if recs[0].Stdin != `{"op":"rootdse"}` {
		t.Errorf("stdin = %q, want the payload verbatim", recs[0].Stdin)
	}
}

// A nil payload is a legitimate operation with no values, and stdin must still
// be closed or the child blocks on ReadToEnd forever.
func TestLocalClosesStdinForAnEmptyPayload(t *testing.T) {
	records := recordFile(t)
	tr := newTransport(t, adlocal.Config{})
	if _, err := tr.Run(context.Background(), "QQA=", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	recs := stubRecords(t, records)
	if len(recs) < 2 || !recs[1].Finished {
		t.Fatalf("the child did not run to completion: %+v", recs)
	}
	if recs[0].Stdin != "" {
		t.Errorf("stdin = %q, want empty", recs[0].Stdin)
	}
}

// A non-zero exit is data, not an error: the envelope parser above the seam
// decides what it means, exactly as with the SSH transport.
func TestLocalReportsExitCodeAndStderrWithoutErroring(t *testing.T) {
	t.Setenv("PWSHSTUB_STDERR", "pwsh: cannot import ActiveDirectory")
	t.Setenv("PWSHSTUB_EXIT", "127")

	tr := newTransport(t, adlocal.Config{})
	res, err := tr.Run(context.Background(), "QQA=", nil)
	if err != nil {
		t.Fatalf("a non-zero exit must not be a transport error: %v", err)
	}
	if res.ExitCode != 127 {
		t.Errorf("ExitCode = %d, want 127", res.ExitCode)
	}
	if res.Stderr != "pwsh: cannot import ActiveDirectory" {
		t.Errorf("Stderr = %q", res.Stderr)
	}
}

// A missing or misspelled PowerShell is a configure-time error naming the path,
// not a failure on the first resource operation.
func TestNewFailsOnAnExecutableItCannotResolve(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "pwsh-that-is-not-there")
	_, err := adlocal.New(adlocal.Config{PwshPath: missing})
	if err == nil {
		t.Fatal("New must refuse a path it cannot resolve")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
	if !strings.Contains(err.Error(), "pwsh-that-is-not-there") {
		t.Errorf("the error must name the path it could not resolve: %v", err)
	}
}

// An invalid configuration is refused by New rather than surviving to the first
// operation, and it is refused as a transport failure.
func TestNewFailsOnAnInvalidConfiguration(t *testing.T) {
	_, err := adlocal.New(adlocal.Config{PwshPath: stubPath, Concurrency: -1})
	if err == nil {
		t.Fatal("New must refuse a negative concurrency")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
}

// An operation that exceeds Timeout is killed and reported as a transport
// failure, never as an Active Directory refusal.
func TestLocalTimeoutKillsTheChild(t *testing.T) {
	records := recordFile(t)
	t.Setenv("PWSHSTUB_SLEEP_MS", "800")

	tr := newTransport(t, adlocal.Config{Timeout: 150 * time.Millisecond})
	start := time.Now()
	_, err := tr.Run(context.Background(), "QQA=", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Run must fail when the operation exceeds the timeout")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("the error must name the timeout: %v", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Errorf("Run took %s; it must not wait for the child", elapsed)
	}

	// The child must be dead, not merely abandoned: an abandoned stub would
	// finish its sleep and record the completion.
	time.Sleep(1200 * time.Millisecond)
	for _, r := range stubRecords(t, records) {
		if r.Finished {
			t.Error("the child ran to completion; the timeout did not kill it")
		}
	}
}

// A cancelled apply must not leave an orphaned pwsh behind.
func TestLocalCancellationKillsTheChild(t *testing.T) {
	records := recordFile(t)
	t.Setenv("PWSHSTUB_SLEEP_MS", "800")

	tr := newTransport(t, adlocal.Config{Timeout: 30 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := tr.Run(ctx, "QQA=", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Run must return when the context expires")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the cause must survive unwrapping: %v", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Errorf("Run took %s; it must not wait for the child", elapsed)
	}

	time.Sleep(1200 * time.Millisecond)
	for _, r := range stubRecords(t, records) {
		if r.Finished {
			t.Error("the child ran to completion; cancellation did not kill it")
		}
	}
}

// The semaphore is why Terraform's default parallelism of 10 cannot put ten
// pwsh processes on the host at once. The gate observes the count rather than
// inferring it from timing.
func TestLocalBoundsConcurrentProcesses(t *testing.T) {
	gate := newGateServer(t)
	tr := newTransport(t, adlocal.Config{Concurrency: 2, Timeout: 30 * time.Second})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = tr.Run(context.Background(), "QQA=", nil)
		}()
	}

	// Long enough for every runnable invocation to reach the gate, so a broken
	// bound has time to show itself.
	time.Sleep(750 * time.Millisecond)
	if got := gate.MaxOpen(); got > 2 {
		t.Errorf("%d stubs were inside the gate at once, want at most 2", got)
	}

	gate.Release()
	wg.Wait()
	if got := gate.MaxOpen(); got > 2 {
		t.Errorf("%d stubs ran at once over the whole run, want at most 2", got)
	}
	if got := gate.MaxOpen(); got < 2 {
		t.Errorf("only %d stub ran at once; the bound is throttling below its own limit", got)
	}
}

// A context that expires while every slot is taken must return, not block for
// the whole transport timeout.
func TestLocalRespectsCancellationWhileWaitingForASlot(t *testing.T) {
	gate := newGateServer(t)
	tr := newTransport(t, adlocal.Config{Concurrency: 1, Timeout: 30 * time.Second})

	go func() { _, _ = tr.Run(context.Background(), "QQA=", nil) }()
	// Let the first Run take the only slot and reach the gate.
	for i := 0; i < 100 && gate.MaxOpen() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if gate.MaxOpen() == 0 {
		t.Fatal("the first Run never reached the gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := tr.Run(ctx, "QQA=", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Run must return when the context expires while it waits for a slot")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run waited %s for a slot; it must honour the context", elapsed)
	}
	gate.Release()
}

func TestLocalStartsTheChildInWorkingDir(t *testing.T) {
	records := recordFile(t)
	dir := t.TempDir()

	tr := newTransport(t, adlocal.Config{WorkingDir: dir})
	if _, err := tr.Run(context.Background(), "QQA=", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	recs := stubRecords(t, records)
	if len(recs) == 0 {
		t.Fatal("the stub recorded nothing")
	}
	// TempDir can sit under a symlinked path — /var on macOS is /private/var —
	// so compare resolved paths rather than the strings.
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := filepath.EvalSymlinks(recs[0].Dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("the child started in %q, want %q", got, want)
	}
}

// Close exists to satisfy the interface. It releases nothing, so it is
// idempotent and the transport is still usable after it — which is what makes
// a client's deferred Close harmless.
func TestCloseIsANoOpAndRepeatable(t *testing.T) {
	tr := newTransport(t, adlocal.Config{})
	if err := tr.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if _, err := tr.Run(context.Background(), "QQA=", nil); err != nil {
		t.Errorf("Run after Close = %v", err)
	}
}

// The transport parses nothing: the envelope, the classification and the pinned
// domain controller all come from above the seam. Configuring a real client
// through the stub is what proves the seam holds.
func TestClientConfiguresThroughTheLocalTransport(t *testing.T) {
	t.Setenv("PWSHSTUB_STDOUT", "<<<TFAD:BEGIN>>>\r\n"+
		`{"ok":true,"data":{"dnsHostName":"dc01.corp.local",`+
		`"defaultNamingContext":"DC=corp,DC=local",`+
		`"schemaNamingContext":"CN=Schema,CN=Configuration,DC=corp,DC=local"}}`+
		"\r\n<<<TFAD:END>>>\r\n")

	tr := newTransport(t, adlocal.Config{})
	client, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr})
	if err != nil {
		t.Fatalf("adpwsh.New over the local transport: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.Server() != "dc01.corp.local" {
		t.Errorf("Server = %q, want dc01.corp.local", client.Server())
	}
	if client.DefaultNamingContext() != "DC=corp,DC=local" {
		t.Errorf("DefaultNamingContext = %q", client.DefaultNamingContext())
	}
}

// A pwsh that produced no envelope is a transport failure, decided above the
// seam. The transport itself must not have looked at the output at all.
func TestMissingEnvelopeIsATransportFailureAboveTheSeam(t *testing.T) {
	t.Setenv("PWSHSTUB_STDOUT", "Import-Module : The specified module was not loaded.")
	t.Setenv("PWSHSTUB_EXIT", "1")

	tr := newTransport(t, adlocal.Config{})
	// Run itself must succeed: a non-zero exit is data.
	res, err := tr.Run(context.Background(), "QQA=", nil)
	if err != nil {
		t.Fatalf("Run must not error on a non-zero exit: %v", err)
	}
	if res.ExitCode != 1 {
		t.Fatalf("ExitCode = %d, want 1", res.ExitCode)
	}
	// The client is what refuses it, and it refuses it as a transport failure.
	if _, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr}); err == nil {
		t.Fatal("adpwsh.New must fail when pwsh produced no envelope")
	} else if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
}
