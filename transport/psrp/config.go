package psrp

import (
	"errors"
	"fmt"
	"time"
)

// Config is everything transport/psrp needs to reach a Windows host over
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
	Concurrency        int
	Timeout            time.Duration
	// IdleTimeout is the WSMan shell lease requested when a pooled client's
	// shell is created. Left unset, go-psrp itself requests a 30-minute lease
	// — verified on the lab as the cause of a WinRM-shell leak: a shell this
	// long-lived easily outlives the short-lived provider process that opened
	// it, and nothing else ever tears it down server-side. Zero means "use
	// the default", not "no timeout" — there is deliberately no way to
	// request an unbounded lease.
	IdleTimeout time.Duration
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
		// pool reconnects transparently (see conn.invalidate in psrp.go), so
		// there is no cost to going lower. Long enough to comfortably exceed
		// the gap between consecutive operations within one Terraform run.
		c.IdleTimeout = 2 * time.Minute
	}
	return c
}

// Validate is called on the raw config, before WithDefaults, so a negative
// concurrency is rejected here rather than silently accepted (WithDefaults
// later defaults an unset value).
func (c Config) Validate() error {
	if c.Host == "" {
		return errors.New("psrp: host is required")
	}
	if c.InsecureSkipVerify && !c.UseTLS {
		return errors.New("psrp: insecure_skip_verify has no effect without use_tls")
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("psrp: concurrency must not be negative (got %d)", c.Concurrency)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("psrp: timeout must not be negative (got %s)", c.Timeout)
	}
	if c.IdleTimeout < 0 {
		return fmt.Errorf("psrp: idle timeout must not be negative (got %s)", c.IdleTimeout)
	}
	return nil
}
