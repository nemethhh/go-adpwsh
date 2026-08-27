package winrm

import (
	"errors"
	"fmt"
	"time"
)

// Config is everything transport/winrm needs to reach a Windows host over
// PSRP/WinRM. Password is a plain string, matching transport/ssh; the provider
// marks it Sensitive and masks it in logs.
type Config struct {
	Host               string
	Port               int
	UseTLS             bool
	InsecureSkipVerify bool
	Username           string
	Password           string
	Domain             string
	SPN                string // default "HTTP/<Host>"
	Realm              string
	Krb5ConfPath       string
	CCachePath         string
	KeytabPath         string
	ConfigurationName  string
	// LanguageMode selects the endpoint's PowerShell language mode: "" or
	// "full" (default — the existing behaviour), or "constrained" for a
	// ConstrainedLanguage sandbox endpoint. See the psrp-constrained-language
	// design doc.
	LanguageMode string
	Concurrency  int
	Timeout      time.Duration
	// IdleTimeout is the WSMan shell lease requested when a pooled client's
	// shell is created. Left unset, go-psrp itself requests a 30-minute lease
	// — verified on the lab as the cause of a WinRM-shell leak: a shell this
	// long-lived easily outlives the short-lived provider process that opened
	// it, and nothing else ever tears it down server-side. Zero means "use
	// the default", not "no timeout": there is deliberately no way to request
	// an unbounded lease, and WithDefaults also floors any too-small positive
	// value so the lease can never be so short the shell gets reaped out from
	// under a live pool.
	IdleTimeout time.Duration
	// ReapAfter is how long a pooled conn may sit idle in the pool — checked
	// in but unused by any Run — before the background reaper (see
	// reapLoop in internal/warm) closes its shell and rebuilds the
	// client, so the next Run through that conn reconnects fresh. This is
	// what actually releases a shell server-side; IdleTimeout only bounds how
	// long a shell nobody reaps stays alive, in case the reaper is somehow
	// never given the chance to run. Zero means "use the default", matching
	// every other duration on this Config. Unlike IdleTimeout, ReapAfter is
	// never serialized into an ISO8601 lease string, so there is no
	// truncation-to-zero failure mode to floor against — Validate rejecting a
	// negative value is the only guard this field needs.
	ReapAfter time.Duration
}

func (c Config) WithDefaults() Config {
	if c.Port == 0 {
		if c.UseTLS {
			c.Port = 5986
		} else {
			c.Port = 5985
		}
	}
	if c.SPN == "" && c.Host != "" {
		c.SPN = "HTTP/" + c.Host
	}
	if c.ConfigurationName == "" {
		c.ConfigurationName = "PowerShell.7"
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4 // pool of independent clients; see the transport
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.IdleTimeout <= 0 {
		// Short enough that an abandoned shell is not worth caring about; the
		// pool reconnects transparently (see the pool's invalidate/rebuild in
		// internal/warm), so there is no cost to going lower. Long enough to
		// comfortably exceed the gap between consecutive operations within
		// one Terraform run.
		c.IdleTimeout = 2 * time.Minute
	} else if c.IdleTimeout < time.Second {
		// Floor a too-small positive value rather than letting it survive to
		// buildPSRPConfig, where int(d.Seconds()) would truncate anything
		// under a second to 0 and emit "PT0S" — a lease the server could
		// reap the shell under instantly, precisely the bug this field
		// exists to prevent.
		c.IdleTimeout = time.Second
	}
	if c.ReapAfter <= 0 {
		// Bursty Terraform runs (configure, a burst of operations, then idle
		// until the process exits) mean a reaper firing this often almost
		// always still catches the process alive, turning shell cleanup into
		// something this package initiates rather than something discovered
		// later as a corpse on the server.
		c.ReapAfter = 30 * time.Second
	}
	return c
}

// Constrained reports whether the endpoint runs in ConstrainedLanguage mode,
// which changes payload delivery and credential construction and forbids the
// ACL ops (their .NET DirectoryServices calls are unavailable under CLM).
func (c Config) Constrained() bool { return c.LanguageMode == "constrained" }

// Validate is called on the raw config, before WithDefaults, so a negative
// concurrency is rejected here rather than silently accepted (WithDefaults
// later defaults an unset value).
func (c Config) Validate() error {
	if c.Host == "" {
		return errors.New("winrm: host is required")
	}
	if c.InsecureSkipVerify && !c.UseTLS {
		return errors.New("winrm: insecure_skip_verify has no effect without use_tls")
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("winrm: concurrency must not be negative (got %d)", c.Concurrency)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("winrm: timeout must not be negative (got %s)", c.Timeout)
	}
	if c.IdleTimeout < 0 {
		return fmt.Errorf("winrm: idle timeout must not be negative (got %s)", c.IdleTimeout)
	}
	if c.ReapAfter < 0 {
		return fmt.Errorf("winrm: reap after must not be negative (got %s)", c.ReapAfter)
	}
	switch c.LanguageMode {
	case "", "full", "constrained":
	default:
		return fmt.Errorf("winrm: language_mode must be \"full\" or \"constrained\" (got %q)", c.LanguageMode)
	}
	return nil
}
