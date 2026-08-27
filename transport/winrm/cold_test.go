package winrm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

const testTimeout = 60 * time.Second

type fakeColdExec struct {
	gotBootstrap string
	gotStdin     []byte
	result       adpwsh.Result
	err          error
}

func (f *fakeColdExec) exec(_ context.Context, encodedBootstrap string, stdin []byte) (adpwsh.Result, error) {
	f.gotBootstrap = encodedBootstrap
	f.gotStdin = stdin
	return f.result, f.err
}
func (f *fakeColdExec) close() error { return nil }

func newColdWithExec(f coldExecutor) *ColdTransport {
	return &ColdTransport{exec: f, timeout: testTimeout, sem: make(chan struct{}, 1)}
}

func TestColdRunWrapsAndBootstraps(t *testing.T) {
	f := &fakeColdExec{result: adpwsh.Result{Stdout: `{"ok":true}`, ExitCode: 0}}
	c := newColdWithExec(f)
	enc := adscript.EncodeCommand("Get-ADUser @common")
	res, err := c.Run(context.Background(), enc, []byte(`{"identity":"krbtgt"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != `{"ok":true}` {
		t.Fatalf("Stdout = %q", res.Stdout)
	}
	// The command line is the FIXED bootstrap, not the op -- that is what removes
	// the command-size limit.
	if f.gotBootstrap != adscript.EncodeCommand(coldBootstrap) {
		t.Errorf("bootstrap not the fixed ReadToEnd+iex: %q", f.gotBootstrap)
	}
	// stdin carries the WRAPPED script (SetIn payload + preamble + op)...
	stdin := string(f.gotStdin)
	if !strings.Contains(stdin, "SetIn") || !strings.Contains(stdin, "Get-ADUser @common") {
		t.Errorf("stdin is not the wrapped script: %q", stdin)
	}
	// ...and the raw payload JSON is base64'd inside SetIn, never present literally.
	if strings.Contains(stdin, `"identity":"krbtgt"`) {
		t.Error("raw payload leaked as plaintext into the wrapped script")
	}
}

// The whole point of the stdin path: a large op must NOT be rejected (unlike the
// old cmd.exe command-line ceiling).
func TestColdRunLargeCommandNotRejected(t *testing.T) {
	f := &fakeColdExec{result: adpwsh.Result{Stdout: "{}", ExitCode: 0}}
	c := newColdWithExec(f)
	huge := adscript.EncodeCommand(strings.Repeat("Get-ADUser; ", 5000)) // ~60KB, far past any cmd-line limit
	if _, err := c.Run(context.Background(), huge, nil); err != nil {
		t.Fatalf("large command must NOT be rejected, got: %v", err)
	}
	if len(f.gotStdin) < 50000 {
		t.Errorf("expected the large op to ride stdin, got %d bytes", len(f.gotStdin))
	}
}

func TestColdRunPropagatesExecError(t *testing.T) {
	want := &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.wait", Err: errors.New("boom")}
	c := newColdWithExec(&fakeColdExec{err: want})
	_, err := c.Run(context.Background(), adscript.EncodeCommand("x"), nil)
	var ae *adpwsh.Error
	if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransport {
		t.Fatalf("want the executor's KindTransport error propagated, got %v", err)
	}
}

func TestColdRunDecodeErrorIsTransport(t *testing.T) {
	c := newColdWithExec(&fakeColdExec{})
	_, err := c.Run(context.Background(), "!!!not-base64!!!", nil)
	var ae *adpwsh.Error
	if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransport {
		t.Fatalf("want KindTransport for a bad encoded command, got %v", err)
	}
}
