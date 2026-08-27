package winrm

import (
	"context"
	"fmt"
	"sync"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	psrp "github.com/smnsjas/go-psrp/client"
)

// coldCommandCeiling bounds the re-encoded command handed to WinRS. A
// cmd.exe-backed WinRS caps the command line near 8191 chars; base64-of-UTF16
// is ~2.7x the source, and the wrapped script (SetIn payload + preload + op)
// grows further. This is the "winrm+cold cannot do large ops" limit — warm has
// none. Matches the ssh transport's largeCommandThreshold intent.
const coldCommandCeiling = 7000

// winrsRunner is the subset of *psrp.Client the cold path uses. It exists so the
// wrap/encode/map/size-guard logic is unit-testable without WinRM.
type winrsRunner interface {
	ConnectWSManOnly(ctx context.Context) error
	ExecuteCmd(ctx context.Context, command string) (*psrp.CmdResult, error)
	Close(ctx context.Context) error
}

// ColdTransport runs one fresh WinRS `pwsh -EncodedCommand` per operation over
// WSMan. No persistent runspace — the slowest WinRM mode; use warm unless you
// specifically need no server-side shell. Satisfies adpwsh.Transport.
type ColdTransport struct {
	runner  winrsRunner
	pwsh    string
	timeout time.Duration
	sem     chan struct{}

	connOnce sync.Once
	connErr  error
}

// NewCold builds a WSMan-only go-psrp client from cfg for cold WinRS execution.
func NewCold(cfg Config) (*ColdTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.NewCold", Err: err}
	}
	cfg = cfg.WithDefaults()
	client, err := newClient(cfg) // shared with the warm path (buildPSRPConfig + psrp.New)
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.NewCold", Err: err}
	}
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	pwsh := cfg.PwshPath
	if pwsh == "" {
		pwsh = "pwsh"
	}
	return &ColdTransport{runner: client, pwsh: pwsh, timeout: cfg.Timeout, sem: make(chan struct{}, conc)}, nil
}

func (t *ColdTransport) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.Run", Err: ctx.Err()}
	}

	script, err := adscript.DecodeCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.Run", Err: err}
	}
	reenc := adscript.EncodeCommand(adscript.WrapFullPayload(script, payload))
	if len(reenc) >= coldCommandCeiling {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.Run",
			Err: fmt.Errorf("operation too large for winrm cold mode (%d-char command exceeds the WinRS limit); use `mode = \"warm\"`, which has no command-size limit", len(reenc))}
	}
	cmd := `"` + t.pwsh + `" -NoProfile -NonInteractive -EncodedCommand ` + reenc

	t.connOnce.Do(func() { t.connErr = t.runner.ConnectWSManOnly(ctx) })
	if t.connErr != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.Run", Err: t.connErr}
	}

	res, err := t.runner.ExecuteCmd(ctx, cmd)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.Run", Err: err}
	}
	// A non-zero exit is data the envelope parser decides on, exactly like the
	// other cold transports.
	return adpwsh.Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode}, nil
}

func (t *ColdTransport) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	return t.runner.Close(ctx)
}

var _ adpwsh.Transport = (*ColdTransport)(nil)
