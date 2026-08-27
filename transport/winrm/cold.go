package winrm

import (
	"context"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// coldBootstrap is the tiny script handed to `<pwsh> -EncodedCommand`. It reads
// the real operation off stdin (the wrapped script, delivered by ColdTransport)
// and runs it. Keeping the command line to this fixed bootstrap is what lets
// winrm+cold carry an arbitrarily large op with NO command-size limit: the op
// rides stdin, never the command line. The wrapped script's own
// [Console]::SetIn (from adscript.WrapFullPayload) redirects [Console]::In to
// the JSON payload before the preamble reads it, so this ReadToEnd of the real
// stdin and the script's ReadToEnd of the payload do not collide.
const coldBootstrap = `$s=[Console]::In.ReadToEnd(); Invoke-Expression $s`

// ColdTransport runs one fresh WinRS shell per operation over WSMan, feeding the
// wrapped op script on stdin to a `<pwsh> -EncodedCommand <bootstrap>` process.
// No persistent runspace -- the slowest WinRM mode; use warm unless you
// specifically need no server-side PowerShell session configuration (e.g. a host
// where PSRP endpoints are disabled but WinRS command execution is allowed).
// Satisfies adpwsh.Transport.
type ColdTransport struct {
	exec    coldExecutor
	timeout time.Duration
	sem     chan struct{}
}

// NewCold builds a cold WinRS transport from cfg. The transport authenticates to
// WinRS as cfg.Username (the transport identity, which needs WinRS shell access
// -- Remote Management Users / an admin; distinct from domain.Credential, the AD
// identity delivered in the payload).
func NewCold(cfg Config) (*ColdTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.NewCold", Err: err}
	}
	cfg = cfg.WithDefaults()
	et, err := newEndTransport(cfg)
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.NewCold", Err: err}
	}
	// Windows PowerShell 5.1 is the always-present engine and the one the script
	// layer targets; it is the right default for the "PSRP disabled, WinRS
	// allowed" host cold exists for. cfg.PwshPath overrides (e.g. "pwsh").
	pwsh := cfg.PwshPath
	if pwsh == "" || pwsh == "pwsh" {
		pwsh = "powershell.exe"
	}
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	return &ColdTransport{
		exec:    &winrsColdExecutor{et: et, pwsh: pwsh, timeout: cfg.Timeout},
		timeout: cfg.Timeout,
		sem:     make(chan struct{}, conc),
	}, nil
}

// Run decodes the encoded command back to script, wraps it with the payload
// (adscript.WrapFullPayload -- the same [Console]::SetIn delivery the warm path
// uses), and hands the wrapped script to the executor over stdin. There is no
// command-size guard: unlike the WinRS/cmd.exe command line (~8191 chars), stdin
// has no length limit.
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
	wrapped := adscript.WrapFullPayload(script, payload)
	return t.exec.exec(ctx, adscript.EncodeCommand(coldBootstrap), []byte(wrapped))
}

func (t *ColdTransport) Close() error {
	return t.exec.close()
}

var _ adpwsh.Transport = (*ColdTransport)(nil)
