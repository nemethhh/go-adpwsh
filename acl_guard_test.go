package adpwsh

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

type constrainedFake struct{ constrained bool }

func (f constrainedFake) Run(context.Context, string, []byte) (Result, error) {
	return Result{}, errors.New("should not run: guard must fire first")
}
func (f constrainedFake) Close() error      { return nil }
func (f constrainedFake) Constrained() bool { return f.constrained }

func TestACLRefusedWhenConstrained(t *testing.T) {
	c := &core{tr: constrainedFake{constrained: true}, retry: RetryConfig{MaxAttempts: 1}}
	err := c.exec(context.Background(), adscript.OpACLGrant, map[string]any{}, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindUnsupported {
		t.Fatalf("want KindUnsupported, got %v", err)
	}
}

func TestNonACLNotRefusedWhenConstrained(t *testing.T) {
	c := &core{tr: constrainedFake{constrained: true}, retry: RetryConfig{MaxAttempts: 1}}
	err := c.exec(context.Background(), adscript.OpOURead, map[string]any{}, nil)
	// The guard must NOT fire for a non-ACL op; it proceeds to Run (which
	// errors here), so we only assert it is not the guard's KindUnsupported.
	var e *Error
	if errors.As(err, &e) && e.Kind == KindUnsupported {
		t.Fatalf("non-ACL op must not be refused as unsupported")
	}
}
