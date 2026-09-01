package winrm

import (
	"context"
	"fmt"
	"strings"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/warm"
)

// minConnectBudget floors each endpoint's per-probe connect window so that,
// however many endpoints share one operation timeout, each still gets a usable
// chance to dial.
const minConnectBudget = 5 * time.Second

// failoverExecutor is a warm.Executor that probes an ordered list of WinRM
// endpoints at Connect time and binds to the first that connects; Execute and
// Close delegate to the bound endpoint. A conn whose shell dies is rebuilt by
// the pool into a fresh (unbound) failoverExecutor, which re-probes from the
// top — so failover is a property of (re)connection, never of resuming an
// in-flight op. (See the design doc's safety spine.)
type failoverExecutor struct {
	endpoints []Config
	// newExec builds a per-endpoint executor. The default wires a real go-psrp
	// client; a test injects stubs. It errors only when the client cannot be
	// constructed, not when it cannot dial — dialing is Connect's job.
	newExec func(Config) (warm.Executor, error)
	active  warm.Executor
}

func newFailoverExecutor(endpoints []Config) *failoverExecutor {
	return &failoverExecutor{
		endpoints: endpoints,
		newExec: func(c Config) (warm.Executor, error) {
			cl, err := newClient(c)
			if err != nil {
				return nil, err
			}
			return &psrpExecutor{client: cl}, nil
		},
	}
}

func (e *failoverExecutor) Connect(ctx context.Context) error {
	var errs []string
	var lastErr error
	for _, ep := range e.endpoints {
		ex, err := e.newExec(ep)
		if err != nil {
			errs = append(errs, ep.Host+": "+err.Error())
			lastErr = err
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, connectBudget(ep.Timeout, len(e.endpoints)))
		err = ex.Connect(cctx)
		cancel()
		if err != nil {
			_ = ex.Close(context.Background())
			errs = append(errs, ep.Host+": "+err.Error())
			lastErr = err
			continue
		}
		e.active = ex
		return nil
	}
	// A single endpoint returns its own raw error, so single-host connect
	// failures read exactly as before (conn.ensureConnected wraps it
	// KindTransport). Multi returns an enumerated aggregate; ensureConnected
	// wraps that KindTransport too.
	if len(e.endpoints) == 1 {
		return lastErr
	}
	return fmt.Errorf("all %d WinRM endpoints failed to connect: %s",
		len(e.endpoints), strings.Join(errs, "; "))
}

func (e *failoverExecutor) Execute(ctx context.Context, wrapped string) (adpwsh.Result, error) {
	return e.active.Execute(ctx, wrapped)
}

func (e *failoverExecutor) Close(ctx context.Context) error {
	if e.active == nil {
		return nil
	}
	return e.active.Close(ctx)
}

// connectBudget is each endpoint's slice of one operation's timeout, floored so
// a black-hole host cannot consume the whole budget before the others are
// tried. The caller's ctx still caps the total (WithTimeout picks the earlier
// deadline), so this only ever shortens a per-probe window, never extends one.
func connectBudget(total time.Duration, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	b := total / time.Duration(n)
	if b < minConnectBudget {
		b = minConnectBudget
	}
	return b
}

var _ warm.Executor = (*failoverExecutor)(nil)
