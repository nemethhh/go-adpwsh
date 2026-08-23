package psrp

import (
	"context"
	"sync"

	adpwsh "github.com/nemethhh/go-adpwsh"
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
	exec executor
	mu   sync.Mutex
	up   bool
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

// Transport runs go-adpwsh commands over PSRP/WinRM via a checkout pool of
// independent clients. It satisfies adpwsh.Transport.
type Transport struct {
	cfg  Config
	idle chan *conn // buffered to Concurrency; every Run checks one out and returns it

	closeOnce sync.Once
	closeErr  error
}

var _ adpwsh.Transport = (*Transport)(nil)

// newClient builds one go-psrp client with a single runspace. Concurrency comes
// from the pool of clients, never from MaxRunspaces (which would race on SetIn).
func newClient(cfg Config) (executor, error) {
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
	for i := 0; i < cfg.Concurrency; i++ {
		c, err := newClient(cfg)
		if err != nil {
			return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "New", Err: err}
		}
		t.idle <- &conn{exec: c}
	}
	return t, nil
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

	if err := c.ensureConnected(ctx); err != nil {
		return adpwsh.Result{}, err
	}

	script, err := decodeEncodedCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Run", Err: err}
	}

	res, err := c.exec.Execute(ctx, buildWrapper(script, payload))
	if err != nil {
		return adpwsh.Result{}, mapExecuteError(err)
	}
	return adpwsh.Result{
		Stdout:   joinObjects(res.Output),
		Stderr:   joinObjects(res.Errors),
		ExitCode: exitCode(res.HadErrors),
	}, nil
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
