package adschema

import (
	"errors"
	"fmt"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	adlocal "github.com/nemethhh/go-adpwsh/transport/local"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

// TransportSpec is everything needed to open a transport. The CLI fills it from
// flags and the lab test fills it from the environment, so both open a
// transport exactly one way.
//
// The exporter opens no transport of its own: local and ssh both already
// satisfy the library, so an export inherits their framing, timeouts and error
// classification, and an operator exports from wherever they already run the
// provider.
type TransportSpec struct {
	Kind     string // "local" or "ssh"
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
}

// Open builds the transport. Validation is the library's — a missing host key
// source or two auth methods produce its message, not a second opinion.
//
// Concurrency is 1: an export is a single execution.
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
	case "":
		return nil, errors.New("--transport is required; pass local or ssh")
	default:
		return nil, fmt.Errorf("unknown transport %q; pass local or ssh", s.Kind)
	}
}
