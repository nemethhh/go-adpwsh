package winrm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	psrp "github.com/smnsjas/go-psrp/client"
)

const testTimeout = 60 * time.Second

type fakeWinRS struct {
	lastCmd string
	result  *psrp.CmdResult
	execErr error
}

func (f *fakeWinRS) ConnectWSManOnly(context.Context) error { return nil }
func (f *fakeWinRS) ExecuteCmd(_ context.Context, cmd string) (*psrp.CmdResult, error) {
	f.lastCmd = cmd
	return f.result, f.execErr
}
func (f *fakeWinRS) Close(context.Context) error { return nil }

func TestColdRunWrapsEncodesAndMaps(t *testing.T) {
	f := &fakeWinRS{result: &psrp.CmdResult{Stdout: `{"ok":true}`, ExitCode: 0}}
	c := &ColdTransport{runner: f, pwsh: "pwsh", timeout: testTimeout, sem: make(chan struct{}, 1)}
	enc := adscript.EncodeCommand("Get-ADUser @common")
	res, err := c.Run(context.Background(), enc, []byte(`{"identity":"krbtgt"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != `{"ok":true}` {
		t.Fatalf("Stdout = %q", res.Stdout)
	}
	// The command must be pwsh -EncodedCommand with a re-encoded WRAPPED script,
	// and must NOT contain the raw payload as script text.
	if !strings.Contains(f.lastCmd, "-EncodedCommand ") {
		t.Errorf("command not -EncodedCommand: %q", f.lastCmd)
	}
	if strings.Contains(f.lastCmd, `"identity":"krbtgt"`) {
		t.Error("raw payload leaked into the command line")
	}
}

func TestColdRunRejectsOversizeCommand(t *testing.T) {
	f := &fakeWinRS{result: &psrp.CmdResult{}}
	c := &ColdTransport{runner: f, pwsh: "pwsh", timeout: testTimeout, sem: make(chan struct{}, 1)}
	huge := adscript.EncodeCommand(strings.Repeat("Get-ADUser; ", 2000)) // > ceiling once wrapped
	_, err := c.Run(context.Background(), huge, nil)
	if err == nil {
		t.Fatal("oversize command must be rejected with a clear error")
	}
	if !strings.Contains(err.Error(), `mode = "warm"`) {
		t.Errorf("error should point at warm mode: %v", err)
	}
}

func TestColdRunExecErrorIsTransport(t *testing.T) {
	f := &fakeWinRS{execErr: errors.New("winrs down")}
	c := &ColdTransport{runner: f, pwsh: "pwsh", timeout: testTimeout, sem: make(chan struct{}, 1)}
	_, err := c.Run(context.Background(), adscript.EncodeCommand("x"), nil)
	var ae *adpwsh.Error
	if !errors.As(err, &ae) || ae.Kind != adpwsh.KindTransport {
		t.Fatalf("want KindTransport, got %v", err)
	}
}
