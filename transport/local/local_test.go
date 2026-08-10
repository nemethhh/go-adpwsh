package local_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
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
