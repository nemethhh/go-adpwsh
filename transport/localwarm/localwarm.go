package localwarm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	"github.com/nemethhh/go-adpwsh/internal/oop"
	"github.com/nemethhh/go-adpwsh/internal/warm"
	"github.com/smnsjas/go-psrpcore/host"
	"github.com/smnsjas/go-psrpcore/pipeline"
	"github.com/smnsjas/go-psrpcore/runspace"
	"github.com/smnsjas/go-psrpcore/serialization"
)

// New builds a local+warm transport: a warm pool of persistent pwsh -SSHServerMode
// runspaces. It resolves pwsh 7 eagerly (a clear configure-time error if absent)
// but does not dial — each pooled conn spawns its child lazily on first Run.
func New(cfg Config) (adpwsh.Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "localwarm.New", Err: err}
	}
	cfg = cfg.WithDefaults()
	pwsh, err := resolvePwsh(cfg)
	if err != nil {
		return nil, err
	}
	build := func() (warm.Executor, error) {
		return &localExecutor{pwsh: pwsh, cfg: cfg, id: uuid.New()}, nil
	}
	wrapper := func(script string, payload []byte) string {
		return adscript.WrapFullPayload(script, payload)
	}
	return warm.New(warm.Params{
		Concurrency: cfg.Concurrency,
		Timeout:     cfg.Timeout,
		ReapAfter:   cfg.ReapAfter,
		Build:       build,
		Wrapper:     wrapper,
		Classifier:  localClassifier{},
	})
}

// localExecutor is one persistent pwsh -SSHServerMode process plus its
// go-psrpcore runspace, driven over go-adpwsh's out-of-proc adapter.
type localExecutor struct {
	pwsh string
	cfg  Config
	id   uuid.UUID

	cmd     *exec.Cmd
	cancel  context.CancelFunc // cancels the PROCESS context (independent of any op ctx)
	adapter *oop.Adapter
	pool    *runspace.Pool
}

// Connect spawns the child and opens the runspace. The child's lifetime is a
// fresh context.Background()-derived context, NOT the op ctx: a warm process
// must outlive the single Run that first dialled it. The op ctx governs only
// the Open handshake. On any failure the child is killed so nothing leaks, and
// the failure is marked pre-send (nothing executed, so a retry is safe).
func (e *localExecutor) Connect(ctx context.Context) error {
	procCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, e.pwsh, "-SSHServerMode", "-NoLogo", "-NoProfile")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return &preSendError{err: fmt.Errorf("stdin pipe: %w", err)}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return &preSendError{err: fmt.Errorf("stdout pipe: %w", err)}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return &preSendError{err: fmt.Errorf("start pwsh: %w", err)}
	}

	adapter := oop.New(stdout, stdin, e.id, e.cfg.ReadTimeout)
	pool := runspace.New(adapter, e.id)
	_ = pool.SetHost(host.NewNullHost()) // avoid nil-host derefs in the runspace
	if err := pool.Open(ctx); err != nil {
		_ = adapter.Close()
		cancel() // kills the child
		return &preSendError{err: fmt.Errorf("runspace open: %w", err)}
	}

	e.cmd, e.cancel, e.adapter, e.pool = cmd, cancel, adapter, pool
	return nil
}

// Execute runs one already-wrapped script as a single pipeline and returns the
// op's stdout (the deserialized PSRP output stream, one object per line, exactly
// as transport/psrp's joinObjects renders it) so the go-adpwsh envelope parser
// above the transport sees identical text on every transport.
//
// Failure classification is deliberately conservative for non-idempotent AD
// writes: only a CreatePipeline failure — the SendCommand packet, which carries
// NO script — is pre-send (safe to retry). Invoke serializes and sends the
// script itself, so an Invoke or Wait failure is NOT provably pre-execution and
// is returned as a plain error: the warm engine invalidates the conn but never
// retries the op. (See classifier.go and transport/psrp's mapExecuteError for
// the same reasoning on the WinRM path.)
func (e *localExecutor) Execute(ctx context.Context, wrapped string) (adpwsh.Result, error) {
	pl, err := e.pool.CreatePipeline(wrapped) // sends the Command-creation packet (no script yet)
	if err != nil {
		return adpwsh.Result{}, &preSendError{err: fmt.Errorf("create pipeline: %w", err)}
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
// child process, in that order: the read loop must stop before cmd.Wait so all
// reads from the stdout pipe have completed (exec.Cmd.StdoutPipe requires this).
func (e *localExecutor) Close(ctx context.Context) error {
	if e.pool != nil {
		_ = e.pool.Close(ctx)
	}
	if e.adapter != nil {
		_ = e.adapter.Close()
	}
	if e.cancel != nil {
		e.cancel() // kill the child
	}
	if e.cmd != nil {
		_ = e.cmd.Wait()
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

var _ warm.Executor = (*localExecutor)(nil)
