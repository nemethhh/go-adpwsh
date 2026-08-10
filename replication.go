package adpwsh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// replicate performs the post-write replication wait. It returns nil when the
// wait is disabled, when there is nothing to wait for, or when every target
// has the object. On timeout it returns KindReplication, which is never
// retried: the caller must persist the model it holds and surface the error.
func (c *core) replicate(ctx context.Context, guid string) error {
	if !c.repl.Wait {
		return nil
	}
	targets, err := c.replicationTargets(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	if c.repl.ForceSync {
		// A failed forced sync is not fatal on its own: the poll below decides
		// whether the object actually arrived.
		if err := c.exec(ctx, adscript.OpReplicate, map[string]any{
			"identity": guid,
			"source":   c.server,
			"targets":  targets,
		}, nil); err != nil {
			c.debug(ctx, "adpwsh: forced replication failed; falling back to polling", "error", err.Error())
		}
	}

	deadline := time.Now().Add(c.repl.Timeout)
	var pending []string
	for {
		var out struct {
			Results []struct {
				Target  string `json:"target"`
				Present bool   `json:"present"`
			} `json:"results"`
		}
		if err := c.exec(ctx, adscript.OpReplicateVerify, map[string]any{
			"identity": guid,
			"targets":  targets,
		}, &out); err != nil {
			return err
		}
		pending = pending[:0]
		for _, r := range out.Results {
			if !r.Present {
				pending = append(pending, r.Target)
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return &Error{
				Kind:     KindReplication,
				Op:       "Replication.Wait",
				Identity: "guid:" + guid,
				Err: fmt.Errorf("object did not reach %s within %s (source %s)",
					strings.Join(pending, ", "), c.repl.Timeout, c.server),
			}
		}
		t := time.NewTimer(c.repl.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return &Error{Kind: KindTransport, Op: "Replication.Wait", Err: ctx.Err()}
		case <-t.C:
		}
	}
}

// replicationTargets resolves the configured targets, expanding the single
// element "all" through Get-ADDomainController and always excluding the
// pinned source, which by definition already has the write.
func (c *core) replicationTargets(ctx context.Context) ([]string, error) {
	configured := c.repl.Targets
	if len(configured) == 1 && strings.EqualFold(configured[0], "all") {
		var out struct {
			HostNames []string `json:"hostNames"`
		}
		if err := c.exec(ctx, adscript.OpDCList, map[string]any{}, &out); err != nil {
			return nil, err
		}
		configured = out.HostNames
	}
	targets := make([]string, 0, len(configured))
	for _, t := range configured {
		if t == "" || strings.EqualFold(t, c.server) {
			continue
		}
		targets = append(targets, t)
	}
	return targets, nil
}
