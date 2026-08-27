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

// Dial validates cfg and connects to the jump box, returning a live client.
// It is shared with transport/sshwarm, which needs the same auth/host-key
// handling to open its subsystem channel. cfg is validated and defaulted here
// (WithDefaults is idempotent, so callers that already defaulted are safe).
func Dial(cfg Config) (*ssh.Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Dial", Err: err}
	}
	cfg = cfg.WithDefaults()

	auth, err := cfg.authMethods()
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Dial", Err: err}
	}
	hostKey, err := cfg.hostKeyCallback()
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "ssh.Dial", Err: err}
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         cfg.Timeout,
	})
	if err != nil {
		return nil, &adpwsh.Error{
			Kind: adpwsh.KindTransport,
			Op:   "ssh.Dial",
			Err:  fmt.Errorf("cannot connect to %s as %s: %w", addr, cfg.User, err),
		}
	}
	return client, nil
}

// dial returns the transport's cached client, dialling once on first use.
func (t *Transport) dial() (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	client, err := Dial(t.cfg)
	if err != nil {
		return nil, err
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
		// under largeCommandThreshold. PwshPath is quoted unconditionally
		// (safe even for the space-free default "pwsh") because the real
		// install path, e.g. "C:\Program Files\PowerShell\7\pwsh.exe",
		// contains a space cmd.exe would otherwise split on.
		cmd := `"` + t.cfg.PwshPath + `" -NoProfile -NonInteractive -EncodedCommand ` + encodedCommand
		return t.runOnSession(ctx, client, cmd, payload)
	}
	return t.runLarge(ctx, client, encodedCommand, payload)
}

// runLarge is the SFTP fallback for a command too large for -EncodedCommand.
// It decodes the script, writes it to a randomly named file under
// cfg.RemoteTempDir over one SFTP channel, closes that channel, runs the file
// with -File on a fresh exec channel, and finally reopens a short-lived SFTP
// channel to remove it — so at most one channel is ever open at a time per
// operation, matching the package's "fresh channel per operation" invariant
// and the Concurrency/MaxSessions sizing that assumes it.
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
	// ordinary OS temp directory. TrimRight strips a trailing separator so a
	// configured value ending in "/" or "\" doesn't produce a doubled slash.
	dir := strings.TrimRight(strings.ReplaceAll(t.cfg.RemoteTempDir, `\`, "/"), "/")
	remote := dir + "/adpwsh-" + hex.EncodeToString(nonce[:]) + ".ps1"

	client, writeErr := t.writeScriptOverSFTP(client, remote, script)
	// Best-effort cleanup runs whenever a remote path was chosen, even if the
	// write itself failed partway (e.g. Create succeeded but Write did not):
	// an orphaned .ps1 on the jump box must not leak silently. It never
	// surfaces its own error, so it can never mask the op's real result.
	defer t.cleanupRemoteScript(client, remote)
	if writeErr != nil {
		return adpwsh.Result{}, writeErr
	}

	// -EncodedCommand bypasses PowerShell's execution policy; -File does not,
	// so a GPO-hardened host (AllSigned/Restricted) would otherwise refuse
	// every large op with "running scripts is disabled on this system."
	// -ExecutionPolicy Bypass makes -File behave like -EncodedCommand did.
	// PwshPath is quoted for the same reason as the small-command path above.
	cmd := `"` + t.cfg.PwshPath + `" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "` + remote + `"`
	return t.runOnSession(ctx, client, cmd, payload)
}

// writeScriptOverSFTP writes script to remote over an SFTP channel opened on
// client, closing that channel before returning either way. If the write
// fails, it reconnects once and retries the whole write phase — mirroring
// runOnSession's dead-client handling — and returns the client the caller
// should use from here on (the reconnected one, if a reconnect happened). A
// write that still fails after the retry comes back as KindTransient, the
// same as runOnSession's exhausted retry, so core's retry loop gets a chance
// rather than being handed a non-retryable transport error.
func (t *Transport) writeScriptOverSFTP(client *ssh.Client, remote, script string) (*ssh.Client, error) {
	if err := writeSFTPFile(client, remote, script); err == nil {
		return client, nil
	}

	// A dead client is worth one reconnect: a provider outlives sshd's idle
	// timeouts.
	t.reset()
	newClient, dialErr := t.dial()
	if dialErr != nil {
		return newClient, dialErr
	}
	if err := writeSFTPFile(newClient, remote, script); err != nil {
		return newClient, &adpwsh.Error{
			Kind: adpwsh.KindTransient,
			Op:   "ssh.Run",
			Err:  fmt.Errorf("cannot write the large-command script over SFTP: %w", err),
		}
	}
	return newClient, nil
}

// writeSFTPFile opens one SFTP channel on client, writes script to remote,
// and closes the channel before returning.
func writeSFTPFile(client *ssh.Client, remote, script string) error {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("cannot open an SFTP session: %w", err)
	}
	defer sc.Close()

	f, err := sc.Create(remote)
	if err != nil {
		return fmt.Errorf("cannot create %s over SFTP: %w", remote, err)
	}
	if _, err := f.Write([]byte(script)); err != nil {
		_ = f.Close()
		return fmt.Errorf("cannot write %s over SFTP: %w", remote, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot finalize %s over SFTP: %w", remote, err)
	}
	return nil
}

// cleanupRemoteScript best-effort removes the large-command temp file after
// the op has run (or failed to). It opens its own short-lived SFTP channel —
// never reusing one already closed — so that at most one channel is open at
// a time per operation. Every failure here is swallowed: a leaked temp file
// is worth accepting rather than masking the op's actual result.
func (t *Transport) cleanupRemoteScript(client *ssh.Client, remote string) {
	if client == nil {
		return
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		return
	}
	defer sc.Close()
	_ = sc.Remove(remote)
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
