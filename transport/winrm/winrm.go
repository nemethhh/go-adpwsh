package winrm

import (
	"context"
	"fmt"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/warm"
	psrp "github.com/smnsjas/go-psrp/client"
)

// buildPSRPConfig translates our Config into the go-psrp client Config. It is
// split out from newClient so a test can inspect exactly what gets sent over
// the wire, in particular the IdleTimeout translation below.
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
func newClient(cfg Config) (*psrp.Client, error) {
	pc := buildPSRPConfig(cfg)
	return psrp.New(cfg.Host, pc)
}

// psrpExecutor adapts a go-psrp client to warm.Executor, mapping *psrp.Result
// into a neutral adpwsh.Result. This is the only place go-psrp's Result is seen.
type psrpExecutor struct{ client *psrp.Client }

func (e *psrpExecutor) Connect(ctx context.Context) error { return e.client.Connect(ctx) }

func (e *psrpExecutor) Execute(ctx context.Context, wrapped string) (adpwsh.Result, error) {
	res, err := e.client.Execute(ctx, wrapped)
	if err != nil {
		return adpwsh.Result{}, err // raw; warm classifies via winrmClassifier
	}
	return adpwsh.Result{
		Stdout:   joinObjects(res.Output),
		Stderr:   joinObjects(res.Errors),
		ExitCode: exitCode(res.HadErrors),
	}, nil
}

func (e *psrpExecutor) Close(ctx context.Context) error { return e.client.Close(ctx) }

// winrmClassifier injects the WinRM/go-psrp error detection into warm's policy.
// warm owns the retry policy; this owns the transport-specific detection.
type winrmClassifier struct{}

func (winrmClassifier) MapError(err error) error { return mapExecuteError(err) }
func (winrmClassifier) DeadShell(err error) bool { return isDeadShellFailure(err) }

// Transport is the WinRM warm transport: a warm.Pool plus the Constrained()
// signal the top-level client probes for. Run/Close are the embedded pool's.
type Transport struct {
	*warm.Pool
	constrained bool
}

// Constrained reports whether this endpoint runs in ConstrainedLanguage mode.
// core.exec uses this (via an optional interface) to refuse the ACL ops.
func (t *Transport) Constrained() bool { return t.constrained }

var _ adpwsh.Transport = (*Transport)(nil)

// New validates the configuration, then builds a warm client pool wired with
// the WinRM executor, wrapper and classifier. It does not dial; each client
// connects lazily the first time it is checked out, so the operation ctx
// governs the dial and a transient failure does not permanently poison that
// client.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.New", Err: err}
	}
	cfg = cfg.WithDefaults()
	cache := newNegativeCache(negativeCacheCooldown)
	build := func() (warm.Executor, error) {
		return newFailoverExecutor(cfg.resolvedEndpoints(), cache), nil
	}
	wrapper := func(script string, payload []byte) string {
		return buildWrapper(script, payload, cfg.Constrained())
	}
	pool, err := warm.New(warm.Params{
		Concurrency: cfg.Concurrency,
		Timeout:     cfg.Timeout,
		ReapAfter:   cfg.ReapAfter,
		Build:       build,
		Wrapper:     wrapper,
		Classifier:  winrmClassifier{},
	})
	if err != nil {
		return nil, err
	}
	return &Transport{Pool: pool, constrained: cfg.Constrained()}, nil
}
