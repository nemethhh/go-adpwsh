package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// waitDelay bounds how long Wait may block on the output pipes after the child
// has exited. Without it a grandchild that outlived the kill would hang Run
// forever holding the write end open.
const waitDelay = 5 * time.Second

// Transport runs PowerShell as a child process of the caller.
type Transport struct {
	cfg  Config
	pwsh string // the resolved executable, from LookPath
	sem  chan struct{}
}

// New validates the configuration and resolves PwshPath on PATH, so a missing
// or misspelled PowerShell is a configure-time error naming the path rather
// than a failure on the first resource operation.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "local.New", Err: err}
	}
	cfg = cfg.WithDefaults()

	pwsh, err := exec.LookPath(cfg.PwshPath)
	if err != nil {
		return nil, &adpwsh.Error{
			Kind: adpwsh.KindTransport,
			Op:   "local.New",
			Err:  fmt.Errorf("cannot find PowerShell 7 at %q: %w", cfg.PwshPath, err),
		}
	}
	return &Transport{cfg: cfg, pwsh: pwsh, sem: make(chan struct{}, cfg.Concurrency)}, nil
}

// Run executes one operation in a fresh pwsh process.
func (t *Transport) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	// Bound the processes. Each one pays its own Import-Module ActiveDirectory
	// and costs real memory, and Terraform's default parallelism is 10.
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "local.Run", Err: ctx.Err()}
	}

	// The command is fixed text plus a base64 argument, exactly as the
	// Transport contract documents. Nothing the caller supplies reaches argv.
	cmd := exec.Command(t.pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand)
	cmd.Dir = t.cfg.WorkingDir
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = sysProcAttr()
	cmd.WaitDelay = waitDelay

	if err := cmd.Start(); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "local.Run",
			Err: fmt.Errorf("cannot start %s: %w", t.pwsh, err),
		}
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(t.cfg.Timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		killTree(cmd.Process)
		<-done // reap the child rather than leaving it to the collector
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "local.Run", Err: ctx.Err()}

	case <-timer.C:
		killTree(cmd.Process)
		<-done
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "local.Run",
			Err: fmt.Errorf("operation exceeded the %s transport timeout", t.cfg.Timeout),
		}

	case err := <-done:
		res := adpwsh.Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if err == nil {
			return res, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// A non-zero exit is data: the envelope parser decides what it
			// means. Only a failure to run at all is a transport error.
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "local.Run", Err: err}
	}
}

// Close satisfies the Transport interface. There is no persistent connection to
// release: each operation is its own process, and Run has already reaped it.
func (t *Transport) Close() error { return nil }

var _ adpwsh.Transport = (*Transport)(nil)
