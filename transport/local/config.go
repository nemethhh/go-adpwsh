// Package local is the transport that runs PowerShell on the machine the caller
// itself runs on. One pwsh process per operation: there is no session to
// amortize, and a fresh process is what keeps every operation stateless, so a
// failure cannot corrupt the ones that follow.
//
// It is the sibling of transport/ssh, and it deliberately parses nothing.
// Envelope framing, JSON decoding and error classification all live above the
// Transport seam, so this package inherits every correctness property already
// proven for SSH and no transport can reinterpret an Active Directory refusal
// as a transport failure.
package local

import (
	"fmt"
	"os"
	"time"
)

// Config configures the local PowerShell transport.
type Config struct {
	// PwshPath is the PowerShell 7 executable. New resolves it on PATH, so a
	// missing or misspelled PowerShell is a configure-time error naming the
	// path rather than a failure on the first resource operation. Defaults to
	// "pwsh".
	PwshPath string

	// Concurrency bounds simultaneous pwsh processes, as transport/ssh bounds
	// channels. Each process is real memory and pays its own
	// Import-Module ActiveDirectory, and Terraform's default parallelism is 10,
	// so an unbounded transport is how the host runs out of memory. Defaults
	// to 4.
	Concurrency int

	// Timeout is the ceiling on a single operation. Defaults to 60s.
	Timeout time.Duration

	// WorkingDir is the directory each pwsh starts in. Empty means the
	// caller's own working directory.
	WorkingDir string
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
	return c
}

// Validate checks everything that can be checked before a process exists.
// Resolving PwshPath is New's job, because it depends on PATH.
func (c Config) Validate() error {
	if c.Concurrency < 0 {
		return fmt.Errorf("local: concurrency must not be negative (got %d)", c.Concurrency)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("local: timeout must not be negative (got %s)", c.Timeout)
	}
	if c.WorkingDir != "" {
		info, err := os.Stat(c.WorkingDir)
		if err != nil {
			return fmt.Errorf("local: cannot use working_dir %q: %w", c.WorkingDir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("local: working_dir %q is not a directory", c.WorkingDir)
		}
	}
	return nil
}
