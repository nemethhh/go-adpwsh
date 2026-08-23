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
	return c
}

// Validate is called on the raw config, before WithDefaults, so a negative
// concurrency is caught before it is normalised to 1.
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
	return nil
}
