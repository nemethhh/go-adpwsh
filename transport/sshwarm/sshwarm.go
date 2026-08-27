package sshwarm

import (
	"context"
	"fmt"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	"github.com/nemethhh/go-adpwsh/internal/psrun"
	"github.com/nemethhh/go-adpwsh/internal/warm"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

// New builds an ssh+warm transport: a warm pool of persistent pwsh -sshs
// runspaces on a jump box, each reached over its own SSH subsystem channel. It
// validates the config but does not dial — each pooled conn opens its channel
// lazily on first Run (matching transport/winrm and localwarm; unlike
// transport/ssh, which dials eagerly). The runspace executor is shared with
// local+warm via internal/psrun; only the channel Opener differs.
func New(cfg Config) (adpwsh.Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "sshwarm.New", Err: err}
	}
	cfg = cfg.WithDefaults()
	build := func() (warm.Executor, error) {
		return psrun.NewExecutor(subsystemOpener(cfg), cfg.ReadTimeout), nil
	}
	wrapper := func(script string, payload []byte) string {
		return adscript.WrapFullPayload(script, payload)
	}
	return warm.New(warm.Params{
		Concurrency: cfg.SSH.Concurrency,
		Timeout:     cfg.SSH.Timeout,
		ReapAfter:   cfg.ReapAfter,
		Build:       build,
		Wrapper:     wrapper,
		Classifier:  psrun.Classifier{},
	})
}

// subsystemOpener dials the jump box and requests the pwsh subsystem, yielding a
// clean binary out-of-proc stream. A subsystem is mandatory: a plain exec of
// pwsh -sshs is corrupted by the remote cmd.exe. Channel.Close tears down the
// session and the client so sshd reaps the remote pwsh; nothing leaks. Every
// failure here is pre-send (nothing executed yet), so the warm engine may retry.
func subsystemOpener(cfg Config) psrun.Opener {
	return func(ctx context.Context) (*psrun.Channel, error) {
		client, err := adssh.Dial(cfg.SSH)
		if err != nil {
			return nil, psrun.PreSend(fmt.Errorf("ssh dial: %w", err))
		}
		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			return nil, psrun.PreSend(fmt.Errorf("ssh session: %w", err))
		}
		stdin, err := session.StdinPipe()
		if err != nil {
			_ = session.Close()
			_ = client.Close()
			return nil, psrun.PreSend(fmt.Errorf("stdin pipe: %w", err))
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			_ = session.Close()
			_ = client.Close()
			return nil, psrun.PreSend(fmt.Errorf("stdout pipe: %w", err))
		}
		if err := session.RequestSubsystem(cfg.Subsystem); err != nil {
			_ = session.Close()
			_ = client.Close()
			return nil, psrun.PreSend(fmt.Errorf("request subsystem %q (is it registered in sshd_config?): %w", cfg.Subsystem, err))
		}
		return &psrun.Channel{
			R: stdout, W: stdin,
			Close: func() error { _ = session.Close(); return client.Close() },
		}, nil
	}
}
