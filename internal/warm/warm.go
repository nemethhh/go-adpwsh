package warm

import (
	"context"
	"errors"
	"sync"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
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
// connects lazily on first checkout. (Populated in Task 2.)
func New(p Params) (*Pool, error) {
	return nil, errors.New("warm.New: not implemented")
}
