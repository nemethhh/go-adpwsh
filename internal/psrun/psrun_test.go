package psrun

import (
	"errors"
	"fmt"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func TestClassifierDeadShellOnlyForPreSend(t *testing.T) {
	var c Classifier
	if !c.DeadShell(PreSend(errors.New("pipe closed before invoke"))) {
		t.Error("pre-send failure must be a dead shell (retryable)")
	}
	// errors.As must reach a wrapped pre-send marker too.
	if !c.DeadShell(fmt.Errorf("outer: %w", PreSend(errors.New("pipe closed before invoke")))) {
		t.Error("a wrapped pre-send failure must still be a dead shell")
	}
	if c.DeadShell(errors.New("failed mid-pipeline")) {
		t.Error("non-pre-send failure must NOT be a dead shell (unsafe to retry)")
	}
}

func TestClassifierMapErrorKindTransport(t *testing.T) {
	var c Classifier
	var ae *adpwsh.Error
	if !errors.As(c.MapError(errors.New("boom")), &ae) || ae.Kind != adpwsh.KindTransport {
		t.Error("failures classify as KindTransport")
	}
}
