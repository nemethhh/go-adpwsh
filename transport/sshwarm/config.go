package sshwarm

import (
	"time"

	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

// Config configures the ssh+warm transport: a pool of persistent pwsh -sshs
// runspaces on a Windows jump box, reached over an SSH subsystem channel and
// driven over the out-of-proc adapter. Connection, auth and host-key handling
// are the ssh transport's, embedded verbatim; only the subsystem name and the
// warm pool's timings are added here.
type Config struct {
	// SSH is the jump-box connection config: host/port/user, one credential
	// source, and a host-key policy. Reused from transport/ssh (its Dial opens
	// the subsystem channel). SSH.Concurrency is the warm pool size.
	SSH adssh.Config

	// Subsystem is the sshd Subsystem name that launches pwsh -sshs on the jump
	// box (see the sshd_config Subsystem entry). Defaults to "powershell".
	Subsystem string

	// ReapAfter is how long a pooled runspace may sit idle before it is torn
	// down and its remote pwsh reaped. A reaped conn re-warms on next use.
	// Defaults to 30s.
	ReapAfter time.Duration

	// ReadTimeout bounds a single blocking read on the out-of-proc stream so a
	// wedged remote pwsh cannot hang a Read forever. Defaults to 60s.
	ReadTimeout time.Duration
}

// WithDefaults fills the unset fields, including the embedded ssh config.
func (c Config) WithDefaults() Config {
	c.SSH = c.SSH.WithDefaults()
	if c.Subsystem == "" {
		c.Subsystem = "powershell"
	}
	if c.ReapAfter <= 0 {
		c.ReapAfter = 30 * time.Second
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 60 * time.Second
	}
	return c
}

// Validate reuses the ssh transport's host/auth/host-key validation.
func (c Config) Validate() error {
	return c.SSH.Validate()
}
