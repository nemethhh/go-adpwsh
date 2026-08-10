package ssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// Transport runs PowerShell on a Windows jump box over SSH.
type Transport struct {
	cfg Config
	sem chan struct{}

	mu     sync.Mutex
	client *ssh.Client
}

// New validates the configuration and dials the jump box, so a bad credential
// or an unknown host key surfaces at configure time rather than on the first
// resource operation.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.New", Err: err}
	}
	cfg = cfg.WithDefaults()

	t := &Transport{cfg: cfg, sem: make(chan struct{}, cfg.Concurrency)}
	if _, err := t.dial(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) dial() (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}

	auth, err := t.cfg.authMethods()
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.New", Err: err}
	}
	hostKey, err := t.cfg.hostKeyCallback()
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.New", Err: err}
	}

	addr := net.JoinHostPort(t.cfg.Host, strconv.Itoa(t.cfg.Port))
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            t.cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         t.cfg.Timeout,
	})
	if err != nil {
		return nil, &adpwsh.Error{
			Kind: adpwsh.KindTransport,
			Op:   "ssh.New",
			Err:  fmt.Errorf("cannot connect to %s as %s: %w", addr, t.cfg.User, err),
		}
	}
	t.client = client
	return client, nil
}

// Run executes one operation on a fresh channel.
func (t *Transport) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	// Bound the channels. Exceeding sshd's MaxSessions is how an unbounded
	// provider takes the jump box down under Terraform's default parallelism.
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Run", Err: ctx.Err()}
	}

	client, err := t.dial()
	if err != nil {
		return adpwsh.Result{}, err
	}
	session, err := client.NewSession()
	if err != nil {
		// A dead client is worth one reconnect: a provider outlives sshd's
		// idle timeouts.
		t.reset()
		client, dialErr := t.dial()
		if dialErr != nil {
			return adpwsh.Result{}, dialErr
		}
		session, err = client.NewSession()
		if err != nil {
			return adpwsh.Result{}, &adpwsh.Error{
				Kind: adpwsh.KindTransient, // channel exhaustion is worth retrying
				Op:   "ssh.Run",
				Err:  fmt.Errorf("cannot open a session channel: %w", err),
			}
		}
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = bytes.NewReader(payload)

	// The command is fixed text plus a base64 argument whose alphabet passes
	// through cmd.exe unmangled, which is what makes the jump box's
	// DefaultShell setting unable to corrupt it.
	cmd := t.cfg.PwshPath + " -NoProfile -NonInteractive -EncodedCommand " + encodedCommand

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Run", Err: ctx.Err()}
	case err := <-done:
		res := adpwsh.Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if err == nil {
			return res, nil
		}
		var exitErr *ssh.ExitError
		if asExitError(err, &exitErr) {
			// A non-zero exit is data: the envelope parser decides what it
			// means. Only a failure to run at all is a transport error.
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Run", Err: err}
	case <-time.After(t.cfg.Timeout):
		_ = session.Signal(ssh.SIGKILL)
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("operation exceeded the %s transport timeout", t.cfg.Timeout),
		}
	}
}

func (t *Transport) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
}

// Close releases the connection.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	return err
}

func asExitError(err error, out **ssh.ExitError) bool {
	e, ok := err.(*ssh.ExitError)
	if ok {
		*out = e
	}
	return ok
}

var _ adpwsh.Transport = (*Transport)(nil)
