// Package ssh is the transport that carries go-adpwsh to a Windows jump box.
// One ssh.Client for the transport's lifetime, a fresh channel per operation:
// that amortizes the handshake while keeping every operation stateless, so a
// failure cannot corrupt the ones that follow.
package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config configures the SSH transport.
type Config struct {
	Host string
	Port int
	User string

	// Exactly one of these must resolve to a usable credential.
	PrivateKeyPEM  string
	PrivateKeyPath string
	Password       string
	UseAgent       bool

	// Host key verification, checked in this order: InsecureIgnoreHostKey
	// wins if set, then a pinned HostKey, then KnownHostsFile. Setting both
	// HostKey and KnownHostsFile is an error rather than a silent precedence
	// surprise.
	KnownHostsFile        string
	HostKey               string // an authorized_keys-style line, e.g. "ssh-ed25519 AAAA…"
	InsecureIgnoreHostKey bool

	// Concurrency bounds simultaneous SSH channels. Windows sshd defaults to
	// MaxSessions 10 and Terraform's default parallelism is 10, so an
	// unbounded transport exhausts the jump box.
	Concurrency int
	Timeout     time.Duration
	PwshPath    string
}

// WithDefaults fills the unset fields.
func (c Config) WithDefaults() Config {
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.PwshPath == "" {
		c.PwshPath = "pwsh"
	}
	return c
}

// Validate checks the two precedence rules before anything dials.
func (c Config) Validate() error {
	if c.Host == "" {
		return errors.New("ssh: host is required")
	}
	if c.User == "" {
		return errors.New("ssh: user is required")
	}

	sources := 0
	for _, set := range []bool{c.PrivateKeyPEM != "", c.PrivateKeyPath != "", c.Password != "", c.UseAgent} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("ssh: exactly one of private_key, private_key_path, password or use_agent must be set (found %d)", sources)
	}

	if c.InsecureIgnoreHostKey {
		return nil
	}
	if c.HostKey != "" && c.KnownHostsFile != "" {
		return errors.New("ssh: set host_key or known_hosts_file, not both")
	}
	if c.HostKey == "" && c.KnownHostsFile == "" {
		return errors.New("ssh: a host key source is required; set known_hosts_file, host_key, or insecure_ignore_host_key")
	}
	return nil
}

func (c Config) authMethods() ([]ssh.AuthMethod, error) {
	switch {
	case c.PrivateKeyPEM != "":
		signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("ssh: cannot parse private_key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case c.PrivateKeyPath != "":
		pem, err := os.ReadFile(c.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("ssh: cannot read private_key_path: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("ssh: cannot parse the key at private_key_path: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case c.Password != "":
		return []ssh.AuthMethod{ssh.Password(c.Password)}, nil
	case c.UseAgent:
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("ssh: use_agent is set but SSH_AUTH_SOCK is empty")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("ssh: cannot reach the agent: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(conn).Signers)}, nil
	default:
		return nil, errors.New("ssh: no credential source")
	}
}
