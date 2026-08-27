package localwarm

import (
	"errors"
	"fmt"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func TestClassifierDeadShellOnlyForPreSend(t *testing.T) {
	var c localClassifier
	pre := &preSendError{err: errors.New("pipe closed before invoke")}
	if !c.DeadShell(pre) {
		t.Error("pre-send failure must be a dead shell (retryable)")
	}
	// errors.As must reach a wrapped pre-send marker too.
	if !c.DeadShell(fmt.Errorf("outer: %w", pre)) {
		t.Error("a wrapped pre-send failure must still be a dead shell")
	}
	post := errors.New("failed mid-pipeline")
	if c.DeadShell(post) {
		t.Error("a non-pre-send failure must NOT be treated as dead shell (unsafe to retry)")
	}
}

func TestClassifierMapErrorKindTransport(t *testing.T) {
	var c localClassifier
	var ae *adpwsh.Error
	if !errors.As(c.MapError(errors.New("boom")), &ae) || ae.Kind != adpwsh.KindTransport {
		t.Error("local failures classify as KindTransport")
	}
}
