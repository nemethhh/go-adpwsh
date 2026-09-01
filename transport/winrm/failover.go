package winrm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/warm"
)

// minConnectBudget floors each endpoint's per-probe connect window so that,
// however many endpoints share one operation timeout, each still gets a usable
// chance to dial.
const minConnectBudget = 5 * time.Second

// maxConnectBudget caps each per-endpoint probe so a HUNG endpoint (host up but
// its WinRM handshake stalling, rather than refusing) is abandoned quickly
// instead of consuming Timeout/n of the operation deadline and starving the
// next, healthy endpoint. Lab-proven: with Timeout/n = 45s a stalled primary
// left the healthy secondary too little of a 60s op deadline to connect.
const maxConnectBudget = 15 * time.Second

// negativeCacheCooldown is how long an endpoint whose connect just failed is
// skipped before being probed again. Long enough that a hung/black-hole endpoint
// is not re-probed repeatedly during a run (its full connect budget is the cost
// each time); a recovered peer is picked up on the next process/run or via the
// all-down fallback, so re-preferring it mid-run has no benefit.
const negativeCacheCooldown = 5 * time.Minute

// negativeCache remembers endpoints whose connect recently failed so the
// failover executor can skip a hung/black-hole endpoint instead of paying its
// full connect budget on every reconnection. One cache is shared by every
// pooled failover executor (created in New), so the memory survives the warm
// pool's reap-and-rebuild. Concurrency-safe: pooled connections probe in
// parallel.
type negativeCache struct {
	mu        sync.Mutex
	downUntil map[string]time.Time
	cooldown  time.Duration
	now       func() time.Time // injectable for tests; defaults to time.Now
}

func newNegativeCache(cooldown time.Duration) *negativeCache {
	return &negativeCache{downUntil: map[string]time.Time{}, cooldown: cooldown, now: time.Now}
}

// isDown reports whether host is within its cooldown window.
func (c *negativeCache) isDown(host string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.downUntil[host]
	return ok && c.now().Before(t)
}

// markDown starts (or restarts) host's cooldown.
func (c *negativeCache) markDown(host string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.downUntil[host] = c.now().Add(c.cooldown)
}

// clear forgets host's failure (called after a successful connect).
func (c *negativeCache) clear(host string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.downUntil, host)
}

// failoverExecutor is a warm.Executor that probes an ordered list of WinRM
// endpoints at Connect time and binds to the first that connects; Execute and
// Close delegate to the bound endpoint. A conn whose shell dies is rebuilt by
// the pool into a fresh (unbound) failoverExecutor, which re-probes from the
// top — so failover is a property of (re)connection, never of resuming an
// in-flight op. (See the design doc's safety spine.)
type failoverExecutor struct {
	endpoints []Config
	// cache is the pool-shared negative cache (see negativeCache). Nil-safe:
	// a failoverExecutor built with cache == nil behaves exactly as before
	// this type existed.
	cache *negativeCache
	// newExec builds a per-endpoint executor. The default wires a real go-psrp
	// client; a test injects stubs. It errors only when the client cannot be
	// constructed, not when it cannot dial — dialing is Connect's job.
	newExec func(Config) (warm.Executor, error)
	active  warm.Executor
}

func newFailoverExecutor(endpoints []Config, cache *negativeCache) *failoverExecutor {
	return &failoverExecutor{
		endpoints: endpoints,
		cache:     cache,
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
	// Prefer endpoints not currently in a negative-cache cooldown. If every
	// endpoint is cooling down (total outage, or all just failed), fall back to
	// trying them all — the cache must never make Connect give up without a real
	// attempt.
	candidates := make([]Config, 0, len(e.endpoints))
	for _, ep := range e.endpoints {
		if !e.cache.isDown(ep.Host) {
			candidates = append(candidates, ep)
		}
	}
	if len(candidates) == 0 {
		candidates = e.endpoints
	}

	var errs []string
	var lastErr error
	for _, ep := range candidates {
		ex, err := e.newExec(ep)
		if err != nil {
			e.cache.markDown(ep.Host)
			errs = append(errs, ep.Host+": "+err.Error())
			lastErr = err
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, connectBudget(ep.Timeout, len(candidates)))
		err = ex.Connect(cctx)
		cancel()
		if err != nil {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = ex.Close(closeCtx)
			closeCancel()
			e.cache.markDown(ep.Host)
			errs = append(errs, ep.Host+": "+err.Error())
			lastErr = err
			continue
		}
		e.cache.clear(ep.Host)
		e.active = ex
		return nil
	}
	// A single endpoint returns its own raw error, so single-host connect
	// failures read exactly as before (conn.ensureConnected wraps it
	// KindTransport). Multi returns an enumerated aggregate; ensureConnected
	// wraps that KindTransport too.
	if len(candidates) == 1 {
		return lastErr
	}
	return fmt.Errorf("all %d WinRM endpoints failed to connect: %s",
		len(candidates), strings.Join(errs, "; "))
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

// connectBudget is each endpoint's slice of one operation's timeout, clamped to
// [minConnectBudget, maxConnectBudget]. The ceiling prevents a hung endpoint
// from starving the next one; the floor ensures each still gets a usable chance.
// The caller's ctx still caps the total (WithTimeout picks the earlier
// deadline), so this only ever shortens a per-probe window, never extends one.
func connectBudget(total time.Duration, n int) time.Duration {
	// A single candidate gets the whole operation deadline: with nothing to
	// share the budget with there is no starvation to prevent, and the
	// single-host path must keep its pre-failover connect deadline (the 15s
	// ceiling exists only to stop a hung endpoint from starving a healthy
	// sibling when there are 2+ candidates).
	if n <= 1 {
		return total
	}
	b := total / time.Duration(n)
	if b > maxConnectBudget {
		b = maxConnectBudget
	}
	if b < minConnectBudget {
		b = minConnectBudget
	}
	return b
}

var _ warm.Executor = (*failoverExecutor)(nil)
