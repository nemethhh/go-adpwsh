package psrp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	psrp "github.com/smnsjas/go-psrp/client"
)

// executor is the subset of *psrp.Client the transport uses. It exists so the
// pool/wrapper/reassembly logic is unit-testable with fakes, needing no WinRM.
type executor interface {
	Connect(ctx context.Context) error
	Execute(ctx context.Context, script string) (*psrp.Result, error)
	Close(ctx context.Context) error
}

// conn is one pooled client plus its lazy-connect state. Each conn is a separate
// go-psrp client = separate wsmprovhost process = separate [Console], which is
// what makes concurrent Runs safe (SetIn is process-global).
type conn struct {
	build func() (executor, error) // rebuilds a fresh executor; see invalidate
	exec  executor
	mu    sync.Mutex
	up    bool
}

func (c *conn) ensureConnected(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.up {
		return nil
	}
	if err := c.exec.Connect(ctx); err != nil {
		return &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Connect", Err: err}
	}
	c.up = true
	return nil
}

// invalidate discards the dead client behind conn and replaces it with a
// freshly built one, then marks the conn as needing to (re)connect. Call it
// only when the shell itself is actually suspect: a dead or reaped shell
// must not go on reporting itself connected, or every later Run through this
// pooled conn would fail for the life of the process. Two different failure
// classes must NOT reach this call, for two different reasons: a busy-queue
// sentinel (KindTransient; see mapExecuteError) means the shell is fine and
// nothing was even attempted, and a context cancellation or deadline
// (KindTransport, but see isCallerTimeout) means the caller gave up — that
// says nothing about the shell either. Run's call site checks both before
// invalidating.
//
// Simply flipping a local "connected" flag is not enough: go-psrp's own
// Client tracks its own internal connected state, set only by a successful
// Connect and cleared only by Disconnect or Close (verified against
// client/client.go) — nothing in a failed Execute call resets it, so the same
// Client object would go on reporting itself connected forever even though
// its shell is gone, and a later Connect on it is a silent no-op. Close is
// not a fix either: it permanently sets the client's internal closed flag,
// which then makes any future Connect on that same object fail outright
// ("client is closed") — verified against client/client.go's
// CloseWithStrategy and connectInternal. Recovery therefore has to build a
// brand-new client, not Close-then-Connect the old one. The dead client's
// shell is already gone server-side, so there is nothing left to gracefully
// close; the old client is simply dropped (psrp.New does no network I/O, so
// building its replacement here is cheap).
func (c *conn) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fresh, err := c.build(); err == nil {
		c.exec = fresh
	}
	// If build itself fails, keep the old (dead) exec: ensureConnected will
	// try it again and Execute will fail the same way, surfacing a clear
	// error rather than leaving the conn in a half-built state.
	c.up = false
}

// Transport runs go-adpwsh commands over PSRP/WinRM via a checkout pool of
// independent clients. It satisfies adpwsh.Transport.
type Transport struct {
	cfg  Config
	idle chan *conn // buffered to Concurrency; every Run checks one out and returns it

	closeOnce sync.Once
	closeErr  error
}

var _ adpwsh.Transport = (*Transport)(nil)

// buildPSRPConfig translates our Config into the go-psrp client Config. It is
// split out from newClient — which only returns the executor interface,
// hiding the concrete config — so a test can inspect exactly what gets sent
// over the wire, in particular the IdleTimeout translation below.
func buildPSRPConfig(cfg Config) psrp.Config {
	pc := psrp.DefaultConfig()
	pc.Port = cfg.Port
	pc.UseTLS = cfg.UseTLS
	pc.InsecureSkipVerify = cfg.InsecureSkipVerify
	pc.Timeout = cfg.Timeout
	pc.AuthType = psrp.AuthNegotiate // Kerberos first; NTLM fallback (needs TLS)
	pc.Username = cfg.Username
	pc.Password = cfg.Password
	pc.Domain = cfg.Domain
	pc.TargetSPN = cfg.SPN
	pc.Realm = cfg.Realm
	pc.Krb5ConfPath = cfg.Krb5ConfPath
	pc.CCachePath = cfg.CCachePath
	pc.KeytabPath = cfg.KeytabPath
	pc.ConfigurationName = cfg.ConfigurationName
	pc.MaxRunspaces = 1
	// go-psrp's wsman layer requests a 30-minute shell lease (rsp:IdleTimeOut)
	// whenever this is empty — the root cause of the WinRM-shell leak this
	// field closes (see Config.IdleTimeout). PT<seconds>S is accepted
	// ISO8601 and matches what a live shell reports back (e.g. PT1800.000S
	// for the 30-minute default we are overriding).
	pc.IdleTimeout = fmt.Sprintf("PT%dS", int(cfg.IdleTimeout.Seconds()))
	return pc
}

// newClient builds one go-psrp client with a single runspace. Concurrency comes
// from the pool of clients, never from MaxRunspaces (which would race on SetIn).
func newClient(cfg Config) (executor, error) {
	pc := buildPSRPConfig(cfg)
	return psrp.New(cfg.Host, pc)
}

// New validates the configuration, then builds the client pool. It does not
// dial; each client connects lazily the first time it is checked out, so the
// operation ctx governs the dial and a transient failure does not permanently
// poison that client.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "psrp.New", Err: err}
	}
	cfg = cfg.WithDefaults()
	t := &Transport{cfg: cfg, idle: make(chan *conn, cfg.Concurrency)}
	// One build closure shared by every pooled conn: same cfg each time, so
	// invalidate can rebuild a conn's client without the Transport needing to
	// hold onto anything beyond cfg itself.
	build := func() (executor, error) { return newClient(cfg) }
	for i := 0; i < cfg.Concurrency; i++ {
		c, err := build()
		if err != nil {
			return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "psrp.New", Err: err}
		}
		t.idle <- &conn{exec: c, build: build}
	}
	return t, nil
}

// runOnce connects conn c if needed and executes one already-wrapped script,
// classifying any Execute failure through mapExecuteError.
func runOnce(ctx context.Context, c *conn, wrapped string) (adpwsh.Result, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return adpwsh.Result{}, err
	}
	res, err := c.exec.Execute(ctx, wrapped)
	if err != nil {
		return adpwsh.Result{}, mapExecuteError(err)
	}
	return adpwsh.Result{
		Stdout:   joinObjects(res.Output),
		Stderr:   joinObjects(res.Errors),
		ExitCode: exitCode(res.HadErrors),
	}, nil
}

// Run implements adpwsh.Transport.
func (t *Transport) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	var c *conn
	select {
	case c = <-t.idle:
		defer func() { t.idle <- c }()
	case <-ctx.Done():
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "Run", Err: ctx.Err()}
	}

	script, err := adscript.DecodeCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Run", Err: err}
	}
	wrapped := buildWrapper(script, payload)

	// A plain Connect failure is deliberately not run through
	// invalidate/retry below: ensureConnected already leaves c.up false on
	// failure, so the next checkout retries Connect on this very client —
	// go-psrp only short-circuits Connect when it already believes itself
	// connected (see connectInternal), so a Connect failure never leaves a
	// client stuck reporting false confidence the way a dead-shell Execute
	// failure does. Nothing here needs rebuilding.
	if err := c.ensureConnected(ctx); err != nil {
		return adpwsh.Result{}, err
	}

	res, execErr := c.exec.Execute(ctx, wrapped)
	if execErr == nil {
		return adpwsh.Result{
			Stdout:   joinObjects(res.Output),
			Stderr:   joinObjects(res.Errors),
			ExitCode: exitCode(res.HadErrors),
		}, nil
	}

	mapped := mapExecuteError(execErr)
	var ae *adpwsh.Error
	if !errors.As(mapped, &ae) || ae.Kind == adpwsh.KindTransient {
		// A busy queue: the shell is fine, and the caller will simply try
		// again later. Leave the conn exactly as it was — tearing down a
		// good shell here would be a performance regression, not a fix.
		return adpwsh.Result{}, mapped
	}

	if isCallerTimeout(execErr) {
		// KindTransport (mapExecuteError already refused to call this
		// retryable), but that is a "safe to retry?" answer, not a "is the
		// shell dead?" one — see isCallerTimeout's doc. The caller gave up;
		// the shell is probably still good. Invalidating here would tear
		// down a live client on every timeout and leak it for up to
		// Config.IdleTimeout, undoing the shell-leak fix. Leave the conn
		// alone, exactly as for the transient sentinels above.
		return adpwsh.Result{}, mapped
	}

	// Anything else means the shell itself is suspect (dead, reaped, or the
	// host restarted WinRM). Rebuild the conn unconditionally so a LATER,
	// unrelated Run never inherits a permanently poisoned client — this must
	// happen even for a failure class we choose not to retry below.
	c.invalidate()

	if !isDeadShellFailure(execErr) {
		// Not confirmed to be a pipeline-start failure (see
		// isDeadShellFailure): the script may already have reached Active
		// Directory, so retrying this specific operation is not safe. The
		// conn is already fixed for whatever the caller tries next.
		return adpwsh.Result{}, mapped
	}

	// Exactly one retry, against the freshly rebuilt conn — never a loop: this
	// is the only call to runOnce here, and whatever it returns goes straight
	// back to the caller with no further branching. If the rebuilt client
	// also fails non-transiently, runOnce leaves this conn with c.up == true
	// (ensureConnected succeeded) pointing at a client that just failed to
	// Execute; that is intentionally left alone rather than invalidated again
	// here. It self-heals: the conn goes back to the idle channel via the
	// defer above, and the next Run through it re-triages from the top of
	// this function, invalidating it (again) if it is still bad.
	return runOnce(ctx, c, wrapped)
}

// Close implements adpwsh.Transport. It drains and closes every pooled client;
// it assumes no Run is in flight (the provider closes at shutdown). Close is
// idempotent: a repeated call is a safe no-op returning the first call's
// result, rather than blocking forever on an already-drained idle channel.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		var firstErr error
		for i := 0; i < t.cfg.Concurrency; i++ {
			c := <-t.idle
			c.mu.Lock()
			up := c.up
			c.mu.Unlock()
			if !up {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
			if err := c.exec.Close(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
			cancel()
		}
		t.closeErr = firstErr
	})
	return t.closeErr
}
