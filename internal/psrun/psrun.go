// Package psrun is the shared runspace-executor core for the warm transports
// that drive a pwsh -sshs/-SSHServerMode server over the out-of-proc adapter.
// local+warm and ssh+warm differ only in HOW the byte stream to pwsh is opened;
// everything downstream — the out-of-proc adapter, the go-psrpcore runspace, the
// pipeline per op, output deserialization, and the pre-send-only retry
// classification — is identical and lives here, parameterised by an Opener.
package psrun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/oop"
	"github.com/nemethhh/go-adpwsh/internal/warm"
	"github.com/smnsjas/go-psrpcore/host"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
	"github.com/smnsjas/go-psrpcore/serialization"
)

// Channel is one open byte stream to a pwsh -sshs/-SSHServerMode server. R and W
// are the out-of-proc read/write ends; Close tears the process/session down so
// nothing leaks when a conn is reaped or invalidated.
type Channel struct {
	R     io.Reader
	W     io.Writer
	Close func() error
}

// Opener opens a fresh Channel to a pwsh out-of-proc server. Each pooled
// Executor calls it once on Connect. An Opener marks its own spawn/dial failures
// with PreSend so the warm engine may retry them (nothing executed yet).
type Opener func(ctx context.Context) (*Channel, error)

// preSendError marks a failure that provably occurred BEFORE any part of the
// op's command was transmitted to the runspace — i.e. only the CreatePipeline
// SendCommand packet (which carries no script) failed, or the channel could not
// be opened at all. It is the ONLY class the warm engine may retry
// transparently, because a retry re-runs the op and AD writes are
// non-idempotent.
//
// Deliberately narrow: a failure once Invoke has run is NOT wrapped in this
// type, even though Invoke's send often fails only because the shell is dead.
// Invoke serializes the script and sends the CREATE_PIPELINE message — the
// actual command — so an error there is not provably pre-execution, and the
// op may already have reached AD. That mirrors transport/winrm's classifier,
// which for the same reason refuses to retry a possibly-sent script.
type preSendError struct{ err error }

func (e *preSendError) Error() string { return e.err.Error() }
func (e *preSendError) Unwrap() error { return e.err }

// PreSend wraps err as a confirmed pre-send failure — safe to retry. Openers use
// it to mark spawn/dial failures retryable.
func PreSend(err error) error { return &preSendError{err: err} }

// Classifier injects the warm+runspace error detection into the warm pool's
// retry policy. The pool owns the policy (one retry, dead-shell only); this
// owns the detection.
type Classifier struct{}

// MapError classifies every runspace failure as KindTransport. A warm failure
// is a channel/process failure, never a "provably did not execute" transient,
// so it is never retried on the KindTransient path — only a pre-send dead shell
// (below) is retried, and that is the DeadShell signal.
func (Classifier) MapError(err error) error {
	return &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "psrun", Err: err}
}

// DeadShell reports whether err is a confirmed pre-send failure — the only
// class safe to retry transparently. errors.As unwraps to any depth.
func (Classifier) DeadShell(err error) bool {
	var pse *preSendError
	return errors.As(err, &pse)
}

// Executor is one persistent pwsh out-of-proc process plus its go-psrpcore
// runspace, driven over go-adpwsh's out-of-proc adapter. The Opener supplies the
// byte stream (a local child, or an SSH subsystem channel); everything else is
// transport-agnostic.
type Executor struct {
	open        Opener
	readTimeout time.Duration
	id          uuid.UUID

	ch      *Channel
	adapter *oop.Adapter
	pool    *runspace.Pool
}

// NewExecutor builds an executor that opens its channel with open and bounds a
// single blocking out-of-proc read at readTimeout.
func NewExecutor(open Opener, readTimeout time.Duration) *Executor {
	return &Executor{open: open, readTimeout: readTimeout, id: uuid.New()}
}

// Connect opens the channel and the runspace. The Opener owns the channel's
// lifetime (its Close tears the process/session down); the op ctx governs only
// the Open handshake. On any failure the channel is closed so nothing leaks, and
// the failure is marked pre-send (nothing executed, so a retry is safe).
func (e *Executor) Connect(ctx context.Context) error {
	ch, err := e.open(ctx) // the Opener marks its own failures PreSend
	if err != nil {
		return err
	}
	adapter := oop.New(ch.R, ch.W, e.id, e.readTimeout)
	pool := runspace.New(adapter, e.id)
	_ = pool.SetHost(host.NewNullHost()) // avoid nil-host derefs in the runspace
	if err := pool.Open(ctx); err != nil {
		_ = adapter.Close()
		_ = ch.Close()
		return PreSend(fmt.Errorf("runspace open: %w", err))
	}
	e.ch, e.adapter, e.pool = ch, adapter, pool
	return nil
}

// Execute runs one already-wrapped script as a single pipeline and returns the
// op's stdout (the deserialized PSRP output stream, one object per line, exactly
// as transport/winrm's joinObjects renders it) so the go-adpwsh envelope parser
// above the transport sees identical text on every transport.
//
// Failure classification is deliberately conservative for non-idempotent AD
// writes: only a CreatePipeline failure — the SendCommand packet, which carries
// NO script — is pre-send (safe to retry). Invoke serializes and sends the
// script itself, so an Invoke or Wait failure is NOT provably pre-execution and
// is returned as a plain error: the warm engine invalidates the conn but never
// retries the op. (See the classifier above and transport/winrm's mapExecuteError
// for the same reasoning on the WinRM path.)
func (e *Executor) Execute(ctx context.Context, wrapped string) (adpwsh.Result, error) {
	pl, err := e.pool.CreatePipeline(wrapped) // sends the Command-creation packet (no script yet)
	if err != nil {
		return adpwsh.Result{}, PreSend(fmt.Errorf("create pipeline: %w", err))
	}

	var outParts, errParts []string
	outDone := make(chan struct{})
	errDone := make(chan struct{})
	// Each slice is written ONLY by its own goroutine and read ONLY after the
	// matching done channel closes, so there is no shared-write race.
	go func() {
		d := serialization.NewDeserializer()
		defer d.Close()
		for msg := range pl.Output() {
			if objs, e2 := d.Deserialize(msg.Data); e2 == nil {
				for _, o := range objs {
					outParts = append(outParts, psString(o))
				}
			} else {
				outParts = append(outParts, string(msg.Data)) // fallback: raw CLIXML
			}
		}
		close(outDone)
	}()
	go func() {
		d := serialization.NewDeserializer()
		defer d.Close()
		for msg := range pl.Error() {
			if objs, e2 := d.Deserialize(msg.Data); e2 == nil {
				for _, o := range objs {
					errParts = append(errParts, psString(o))
				}
			} else {
				errParts = append(errParts, string(msg.Data))
			}
		}
		close(errDone)
	}()

	if invokeErr := pl.Invoke(ctx); invokeErr != nil {
		// Invoke sends the CREATE_PIPELINE message carrying the script. A failure
		// here is NOT provably pre-execution — plain error, no pre-send marker.
		return adpwsh.Result{}, fmt.Errorf("invoke pipeline: %w", invokeErr)
	}
	waitErr := pl.Wait()
	<-outDone
	<-errDone

	res := adpwsh.Result{
		Stdout: strings.Join(outParts, "\n"),
		Stderr: strings.Join(errParts, "\n"),
	}
	if waitErr != nil || pl.State() == pipeline.StateFailed {
		// The pipeline ran but ended abnormally (a runspace-level failure, not an
		// AD refusal — the op scripts catch those and emit an ok=false envelope
		// with exit 0). Not provably pre-send: invalidate, never retry.
		res.ExitCode = 1
		return res, fmt.Errorf("pipeline failed: state=%v waitErr=%v", pl.State(), waitErr)
	}
	// Normal completion: the op's JSON envelope is in Stdout; ExitCode 0. The
	// envelope parser above the transport decides AD success/failure.
	return res, nil
}

// Close tears down the runspace, the adapter (which stops its read loop) and the
// channel, in that order: the read loop must stop before the channel's Close so
// all reads from the stream have completed (a child's StdoutPipe requires this).
func (e *Executor) Close(ctx context.Context) error {
	if e.pool != nil {
		_ = e.pool.Close(ctx)
	}
	if e.adapter != nil {
		_ = e.adapter.Close()
	}
	if e.ch != nil {
		_ = e.ch.Close()
	}
	return nil
}

// psString renders one deserialized PSRP output object as text. A plain string
// passes through; a *serialization.PSObject uses its String() (which prefers
// ToString/Value and digs error records out sensibly).
func psString(o interface{}) string {
	type stringer interface{ String() string }
	switch v := o.(type) {
	case string:
		return v
	case stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

var _ warm.Executor = (*Executor)(nil)
var _ warm.Classifier = Classifier{}
