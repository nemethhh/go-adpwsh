package adpwsh

import (
	"context"
	"strings"
	"testing"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// captureFake records the encoded command it is asked to run so the test can
// decode which script core.exec selected, then returns a benign empty envelope.
type captureFake struct {
	constrained bool
	lastScript  string
}

func (f *captureFake) Run(_ context.Context, encoded string, _ []byte) (Result, error) {
	s, _ := adscript.DecodeCommand(encoded)
	f.lastScript = s
	return Result{Stdout: "<<<TFAD:BEGIN>>>\n{\"ok\":true,\"data\":{}}\n<<<TFAD:END>>>"}, nil
}
func (f *captureFake) Close() error      { return nil }
func (f *captureFake) Constrained() bool { return f.constrained }

func TestACLOpSelectsCLMScriptWhenConstrained(t *testing.T) {
	f := &captureFake{constrained: true}
	c := &core{tr: f, retry: RetryConfig{MaxAttempts: 1}}
	_ = c.exec(context.Background(), adscript.OpACLGrant, map[string]any{"target": "x", "aces": []any{}}, nil)
	if !strings.Contains(f.lastScript, "Set-AdAce") {
		t.Fatalf("constrained ACL op must run the _clm script that calls Set-AdAce; got:\n%s", f.lastScript)
	}
}

func TestACLOpSelectsInlineScriptWhenFull(t *testing.T) {
	f := &captureFake{constrained: false}
	c := &core{tr: f, retry: RetryConfig{MaxAttempts: 1}}
	_ = c.exec(context.Background(), adscript.OpACLGrant, map[string]any{"target": "x", "aces": []any{}}, nil)
	if !strings.Contains(f.lastScript, "ActiveDirectoryAccessRule") || strings.Contains(f.lastScript, "Set-AdAce") {
		t.Fatalf("full ACL op must run the inline script; got:\n%s", f.lastScript)
	}
}
