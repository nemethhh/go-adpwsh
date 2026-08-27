package warm

import (
	"context"
	"errors"
	"sync"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// Executor is one warm PSRP connection. Concurrency comes from a POOL of these,
// never from one executor running parallel pipelines.
type Executor interface {
	Connect(ctx context.Context) error
	// Execute runs one already-wrapped script and returns a neutral result.
	// A non-nil error is classified by the pool via Params.Classifier.
	Execute(ctx context.Context, wrapped string) (adpwsh.Result, error)
	Close(ctx context.Context) error
}

// Classifier supplies the transport-specific error detection the pool's retry
// policy needs. The pool owns the policy; the Classifier owns the detection.
type Classifier interface {
	// MapError returns a classified error (typically an *adpwsh.Error). A
	// KindTransient result means "the shell is fine and nothing was attempted".
	MapError(err error) error
	// DeadShell reports whether err is a confirmed pre-execution pipeline-start
	// failure — the only class safe to retry transparently.
	DeadShell(err error) bool
}

// Wrapper embeds the payload into the script for a warm runspace (which has no
// fresh stdin per op). Constrained-ness / transport specifics are baked in by
// the caller that constructs the Wrapper.
type Wrapper func(script string, payload []byte) string

// Params configures a warm Pool.
type Params struct {
	Concurrency int
	Timeout     time.Duration
	ReapAfter   time.Duration
	Build       func() (Executor, error) // builds a fresh executor (used by New and invalidate)
	Wrapper     Wrapper
	Classifier  Classifier
}

// Pool is a checkout pool of warm executors. It satisfies adpwsh.Transport.
type Pool struct {
	params Params
	idle   chan *conn

	closeOnce sync.Once
	closeErr  error
	reapStop  chan struct{}
	reapDone  chan struct{}
}

// New validates params and builds the pool. It does not dial; each executor
// connects lazily on first checkout, so the operation ctx governs the dial
// and a transient failure does not permanently poison that conn.
//
// New requires every Params field already positive/non-nil rather than
// defaulting anything itself: the caller (Config.WithDefaults, in the
// transport package that consumes this pool) is where defaulting belongs —
// New's job is only to refuse to build a pool with a nonsensical config.
func New(p Params) (*Pool, error) {
	switch {
	case p.Concurrency <= 0:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: Concurrency must be > 0")}
	case p.Timeout <= 0:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: Timeout must be > 0")}
	case p.ReapAfter <= 0:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: ReapAfter must be > 0")}
	case p.Build == nil:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: Build must not be nil")}
	case p.Wrapper == nil:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: Wrapper must not be nil")}
	case p.Classifier == nil:
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: errors.New("warm: Classifier must not be nil")}
	}

	t := &Pool{
		params:   p,
		idle:     make(chan *conn, p.Concurrency),
		reapStop: make(chan struct{}),
		reapDone: make(chan struct{}),
	}
	// One Build closure shared by every pooled conn: invalidate can rebuild a
	// conn's executor without the Pool needing to hold onto anything beyond
	// params itself.
	for i := 0; i < p.Concurrency; i++ {
		c, err := p.Build()
		if err != nil {
			return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "warm.New", Err: err}
		}
		t.idle <- &conn{exec: c, build: p.Build}
	}
	// The pool's only background activity: it releases shells this package
	// opened but that nothing else ever tears down. Task 3 replaces this
	// placeholder with the real reapLoop; for now it only exists so Close's
	// close(t.reapStop); <-t.reapDone does not block forever. Started only
	// once every conn is already sitting in t.idle, so it can never race the
	// population loop above.
	go func() { <-t.reapStop; close(t.reapDone) }()
	return t, nil
}

// runOnce connects conn c if needed and executes one already-wrapped script,
// classifying any Execute failure through the pool's Classifier.
func (t *Pool) runOnce(ctx context.Context, c *conn, wrapped string) (adpwsh.Result, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return adpwsh.Result{}, err
	}
	res, err := c.exec.Execute(ctx, wrapped)
	if err != nil {
		return adpwsh.Result{}, t.params.Classifier.MapError(err)
	}
	return res, nil
}

// Run implements adpwsh.Transport.
func (t *Pool) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	var c *conn
	select {
	case c = <-t.idle:
		// Stamped on the way back in, not at checkout, and unconditionally
		// (success or failure): the reaper's idle clock should measure time
		// since this conn was last actually acted on, not time since it was
		// last handed out — a Run in flight is never "idle" in the sense the
		// reaper cares about, but it also holds no lock on lastUsed while
		// running, so there is nothing for the reaper to race here (it can't
		// see this conn at all until this defer returns it to t.idle).
		defer func() {
			c.mu.Lock()
			c.lastUsed = time.Now()
			c.mu.Unlock()
			t.idle <- c
		}()
	case <-ctx.Done():
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "Run", Err: ctx.Err()}
	}

	script, err := adscript.DecodeCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Run", Err: err}
	}
	wrapped := t.params.Wrapper(script, payload)

	// A plain Connect failure is deliberately not run through
	// invalidate/retry below: ensureConnected already leaves c.up false on
	// failure, so the next checkout retries Connect on this very conn —
	// nothing here needs rebuilding.
	if err := c.ensureConnected(ctx); err != nil {
		return adpwsh.Result{}, err
	}

	res, execErr := c.exec.Execute(ctx, wrapped)
	if execErr == nil {
		return res, nil
	}

	mapped := t.params.Classifier.MapError(execErr)
	var ae *adpwsh.Error
	if !errors.As(mapped, &ae) || ae.Kind == adpwsh.KindTransient {
		// A busy queue: the shell is fine, and the caller will simply try
		// again later. Leave the conn exactly as it was — tearing down a
		// good shell here would be a performance regression, not a fix.
		return adpwsh.Result{}, mapped
	}

	if isCallerTimeout(execErr) {
		// KindTransport (the classifier already refused to call this
		// retryable), but that is a "safe to retry?" answer, not a "is the
		// shell dead?" one — see isCallerTimeout's doc. The caller gave up;
		// the shell is probably still good. Invalidating here would tear
		// down a live executor on every timeout and leak it for up to
		// Params.ReapAfter, undoing the shell-leak fix. Leave the conn
		// alone, exactly as for the transient sentinels above.
		return adpwsh.Result{}, mapped
	}

	// Anything else means the shell itself is suspect (dead, reaped, or the
	// host restarted). Rebuild the conn unconditionally so a LATER,
	// unrelated Run never inherits a permanently poisoned executor — this
	// must happen even for a failure class we choose not to retry below.
	c.invalidate()

	if !t.params.Classifier.DeadShell(execErr) {
		// Not confirmed to be a pipeline-start failure: the script may
		// already have reached Active Directory, so retrying this specific
		// operation is not safe. The conn is already fixed for whatever the
		// caller tries next.
		return adpwsh.Result{}, mapped
	}

	// Exactly one retry, against the freshly rebuilt conn — never a loop:
	// this is the only call to runOnce here, and whatever it returns goes
	// straight back to the caller with no further branching. If the
	// rebuilt executor also fails non-transiently, runOnce leaves this conn
	// with c.up == true (ensureConnected succeeded) pointing at an executor
	// that just failed to Execute; that is intentionally left alone rather
	// than invalidated again here. It self-heals: the conn goes back to the
	// idle channel via the defer above, and the next Run through it
	// re-triages from the top of this function, invalidating it (again) if
	// it is still bad.
	return t.runOnce(ctx, c, wrapped)
}

// Close implements adpwsh.Transport. It stops the background reaper, then
// drains and closes every pooled executor; it assumes no Run is in flight
// (the provider closes at shutdown). Close is idempotent: a repeated call is
// a safe no-op returning the first call's result, rather than blocking
// forever on an already-drained idle channel.
func (t *Pool) Close() error {
	t.closeOnce.Do(func() {
		if t.reapStop != nil {
			// Stop the reaper and wait for it to actually be gone *before*
			// touching t.idle at all — this is what makes Close safe against
			// a sweep still in flight, and it is a bounded wait, not a race.
			// Without it, the drain loop below (a fixed Concurrency receives)
			// could interleave with the reaper's own receives from the same
			// channel and silently under-close the pool. Waiting for
			// reapDone guarantees every conn the reaper ever took is back in
			// t.idle before the drain below reads a single one.
			close(t.reapStop)
			<-t.reapDone
		}
		var firstErr error
		for i := 0; i < t.params.Concurrency; i++ {
			c := <-t.idle
			c.mu.Lock()
			up := c.up
			c.mu.Unlock()
			if !up {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), t.params.Timeout)
			if err := c.exec.Close(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
			cancel()
		}
		t.closeErr = firstErr
	})
	return t.closeErr
}
