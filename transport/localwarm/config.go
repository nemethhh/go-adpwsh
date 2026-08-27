package localwarm

import (
	"fmt"
	"os/exec"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// Config configures the local+warm transport: a pool of persistent local
// PowerShell 7 runspaces (pwsh -SSHServerMode) driven over the out-of-proc
// adapter. Unlike transport/local (one pwsh per op), startup and
// Import-Module ActiveDirectory are paid once per pooled process.
type Config struct {
	// PwshPath is the PowerShell 7 executable. Warm mode requires pwsh 7:
	// Windows PowerShell 5.1 cannot serve out-of-proc (it rejects -sshs and
	// -SSHServerMode). New resolves it on PATH, so a missing pwsh is a
	// configure-time error naming the path. Defaults to "pwsh".
	PwshPath string

	// Concurrency bounds simultaneous pwsh processes and is the pool size.
	// Concurrency comes from a pool of processes, never one process running
	// parallel pipelines ([Console]/SetIn is process-global). Defaults to 4.
	Concurrency int

	// Timeout is the ceiling on a single operation. Defaults to 60s.
	Timeout time.Duration

	// ReapAfter is how long a pooled process may sit idle before its runspace
	// is torn down and the child killed, so an idle Terraform run does not hold
	// processes open indefinitely. A reaped conn re-warms on next use. Defaults
	// to 30s.
	ReapAfter time.Duration

	// ReadTimeout bounds a single blocking read on the out-of-proc stream, so a
	// wedged child cannot hang a Read forever. Defaults to 60s.
	ReadTimeout time.Duration
}

// WithDefaults fills the unset fields.
func (c Config) WithDefaults() Config {
	if c.PwshPath == "" {
		c.PwshPath = "pwsh"
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.ReapAfter <= 0 {
		c.ReapAfter = 30 * time.Second
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 60 * time.Second
	}
	return c
}

// Validate checks everything that can be checked before a process exists.
// Resolving PwshPath is New's job, because it depends on PATH. A zero value is
// valid: WithDefaults fills every field.
func (c Config) Validate() error {
	if c.Concurrency < 0 {
		return fmt.Errorf("localwarm: concurrency must not be negative (got %d)", c.Concurrency)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("localwarm: timeout must not be negative (got %s)", c.Timeout)
	}
	if c.ReapAfter < 0 {
		return fmt.Errorf("localwarm: reap_after must not be negative (got %s)", c.ReapAfter)
	}
	if c.ReadTimeout < 0 {
		return fmt.Errorf("localwarm: read_timeout must not be negative (got %s)", c.ReadTimeout)
	}
	return nil
}

// resolvePwsh finds the PowerShell 7 executable on PATH. A missing or misspelled
// pwsh is a configure-time error that names the path and points at local+cold
// for Windows PowerShell 5.1, rather than a failure on the first operation.
func resolvePwsh(cfg Config) (string, error) {
	path, err := exec.LookPath(cfg.PwshPath)
	if err != nil {
		return "", &adpwsh.Error{
			Kind: adpwsh.KindTransport,
			Op:   "localwarm.New",
			Err:  fmt.Errorf("cannot find PowerShell 7 at %q (local+warm requires pwsh 7; use local+cold for Windows PowerShell 5.1): %w", cfg.PwshPath, err),
		}
	}
	return path, nil
}
