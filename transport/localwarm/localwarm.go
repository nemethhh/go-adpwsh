package localwarm

import (
	"context"
	"fmt"
	"os/exec"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	"github.com/nemethhh/go-adpwsh/internal/psrun"
	"github.com/nemethhh/go-adpwsh/internal/warm"
)

// New builds a local+warm transport: a warm pool of persistent pwsh -SSHServerMode
// runspaces. It resolves pwsh 7 eagerly (a clear configure-time error if absent)
// but does not dial — each pooled conn spawns its child lazily on first Run. The
// runspace executor itself lives in internal/psrun, shared with ssh+warm; only
// the child-spawning Opener is local to this package.
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
		return psrun.NewExecutor(childOpener(pwsh), cfg.ReadTimeout), nil
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
		Classifier:  psrun.Classifier{},
	})
}

// childOpener spawns a local pwsh -SSHServerMode child and yields its stdio as an
// out-of-proc Channel. The child's lifetime is a fresh context.Background()-
// derived context, NOT the op ctx: a warm process must outlive the single Run
// that first opened it. Channel.Close cancels that context (killing the child)
// and waits for it, so sshd/exec reaps it and nothing leaks. Every failure here
// is pre-send (nothing executed, so a retry is safe).
func childOpener(pwsh string) psrun.Opener {
	return func(ctx context.Context) (*psrun.Channel, error) {
		procCtx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(procCtx, pwsh, "-SSHServerMode", "-NoLogo", "-NoProfile")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			return nil, psrun.PreSend(fmt.Errorf("stdin pipe: %w", err))
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return nil, psrun.PreSend(fmt.Errorf("stdout pipe: %w", err))
		}
		if err := cmd.Start(); err != nil {
			cancel()
			return nil, psrun.PreSend(fmt.Errorf("start pwsh: %w", err))
		}
		return &psrun.Channel{
			R: stdout, W: stdin,
			// Stop the child before Wait so all reads from the stdout pipe have
			// completed (exec.Cmd.StdoutPipe requires this ordering).
			Close: func() error { cancel(); _ = cmd.Wait(); return nil },
		}, nil
	}
}
