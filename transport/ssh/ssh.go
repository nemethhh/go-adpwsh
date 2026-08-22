package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// largeCommandThreshold is the encoded-command length at and beyond which Run
// switches from -EncodedCommand to the SFTP temp-file fallback. On any
// Windows host whose sshd DefaultShell is cmd.exe, the whole command line —
// pwsh.exe plus its arguments, -EncodedCommand's value included — is capped
// at roughly 8191 characters; composed op scripts base64-encode past that on
// any op with real content. 7000 matches scripts/lab/psrun.sh's cutoff on the
// encoded length, leaving margin for the fixed
// "pwsh -NoProfile -NonInteractive -EncodedCommand " prefix.
const largeCommandThreshold = 7000

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

// Run executes one operation on a fresh channel. Commands short enough for
// -EncodedCommand run directly; at largeCommandThreshold or beyond, the
// script travels to the jump box as a temp file over SFTP and runs by path
// instead (see runLarge).
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

	if len(encodedCommand) < largeCommandThreshold {
		// The command is fixed text plus a base64 argument. Its alphabet
		// passes through cmd.exe unmangled, so quoting can never corrupt it —
		// but the argument still becomes part of the process command line,
		// which a cmd.exe DefaultShell caps at roughly 8191 characters. That
		// length limit, not quoting, is why this path only handles commands
		// under largeCommandThreshold.
		cmd := t.cfg.PwshPath + " -NoProfile -NonInteractive -EncodedCommand " + encodedCommand
		return t.runOnSession(ctx, client, cmd, payload)
	}
	return t.runLarge(ctx, client, encodedCommand, payload)
}

// runLarge is the SFTP fallback for a command too large for -EncodedCommand.
// It decodes the script, writes it to a randomly named file under
// cfg.RemoteTempDir, runs it with -File, and removes it afterward on a
// best-effort basis.
func (t *Transport) runLarge(ctx context.Context, client *ssh.Client, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	script, err := adscript.DecodeCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot decode a large command for the SFTP fallback: %w", err),
		}
	}

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot generate a temp file name: %w", err),
		}
	}
	// Windows OpenSSH's sftp-server also accepts forward slashes, and using
	// them unconditionally is what lets a test point RemoteTempDir at an
	// ordinary OS temp directory.
	dir := strings.ReplaceAll(t.cfg.RemoteTempDir, `\`, "/")
	remote := dir + "/adpwsh-" + hex.EncodeToString(nonce[:]) + ".ps1"

	sc, err := sftp.NewClient(client)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot open an SFTP session: %w", err),
		}
	}
	defer sc.Close()

	f, err := sc.Create(remote)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot create %s over SFTP: %w", remote, err),
		}
	}
	if _, err := f.Write([]byte(script)); err != nil {
		_ = f.Close()
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot write %s over SFTP: %w", remote, err),
		}
	}
	if err := f.Close(); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{
			Kind: adpwsh.KindTransport, Op: "ssh.Run",
			Err: fmt.Errorf("cannot finalize %s over SFTP: %w", remote, err),
		}
	}
	defer func() { _ = sc.Remove(remote) }()

	cmd := t.cfg.PwshPath + ` -NoProfile -NonInteractive -File "` + remote + `"`
	return t.runOnSession(ctx, client, cmd, payload)
}

// runOnSession opens a channel, runs cmd on it with payload on stdin, and
// waits for it to finish — reconnecting once if the client turned out to be
// dead, since a provider outlives sshd's idle timeouts. A non-zero exit is
// data the envelope parser decides on; only a failure to run at all is a
// transport error.
func (t *Transport) runOnSession(ctx context.Context, client *ssh.Client, cmd string, payload []byte) (adpwsh.Result, error) {
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
