package adschema

import (
	"errors"
	"fmt"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	adlocal "github.com/nemethhh/go-adpwsh/transport/local"
	adpsrp "github.com/nemethhh/go-adpwsh/transport/psrp"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

// TransportSpec is everything needed to open a transport. The CLI fills it from
// flags and the lab test fills it from the environment, so both open a
// transport exactly one way.
//
// The exporter opens no transport of its own: local, ssh and psrp all already
// satisfy the library, so an export inherits their framing, timeouts and error
// classification, and an operator exports from wherever they already run the
// provider.
type TransportSpec struct {
	Kind     string // "local", "ssh", or "psrp"
	Timeout  time.Duration
	PwshPath string

	SSHHost                  string
	SSHPort                  int
	SSHUser                  string
	SSHPrivateKeyPath        string
	SSHPassword              string
	SSHKnownHostsFile        string
	SSHHostKey               string
	SSHInsecureIgnoreHostKey bool

	// psrp fields; see transport/psrp.Config for what each one means.
	Host               string
	Port               int
	UseTLS             bool
	InsecureSkipVerify bool
	Username           string
	Password           string
	Domain             string
	SPN                string
	Realm              string
	Krb5ConfPath       string
	CCachePath         string
	KeytabPath         string
	ConfigurationName  string
	Concurrency        int
}

// Open builds the transport. Validation is the library's — a missing host key
// source or two auth methods produce its message, not a second opinion.
//
// Concurrency is 1 for local and ssh; psrp uses the caller-provided concurrency.
func (s TransportSpec) Open() (adpwsh.Transport, error) {
	switch s.Kind {
	case "local":
		return adlocal.New(adlocal.Config{
			PwshPath:    s.PwshPath,
			Concurrency: 1,
			Timeout:     s.Timeout,
		})
	case "ssh":
		return adssh.New(adssh.Config{
			Host:                  s.SSHHost,
			Port:                  s.SSHPort,
			User:                  s.SSHUser,
			PrivateKeyPath:        s.SSHPrivateKeyPath,
			Password:              s.SSHPassword,
			KnownHostsFile:        s.SSHKnownHostsFile,
			HostKey:               s.SSHHostKey,
			InsecureIgnoreHostKey: s.SSHInsecureIgnoreHostKey,
			Concurrency:           1,
			Timeout:               s.Timeout,
			PwshPath:              s.PwshPath,
		})
	case "psrp":
		return adpsrp.New(adpsrp.Config{
			Host:               s.Host,
			Port:               s.Port,
			UseTLS:             s.UseTLS,
			InsecureSkipVerify: s.InsecureSkipVerify,
			Username:           s.Username,
			Password:           s.Password,
			Domain:             s.Domain,
			SPN:                s.SPN,
			Realm:              s.Realm,
			Krb5ConfPath:       s.Krb5ConfPath,
			CCachePath:         s.CCachePath,
			KeytabPath:         s.KeytabPath,
			ConfigurationName:  s.ConfigurationName,
			Concurrency:        s.Concurrency,
			Timeout:            s.Timeout,
		})
	case "":
		return nil, errors.New("--transport is required; pass local, ssh, or psrp")
	default:
		return nil, fmt.Errorf("unknown transport %q; pass local, ssh, or psrp", s.Kind)
	}
}
