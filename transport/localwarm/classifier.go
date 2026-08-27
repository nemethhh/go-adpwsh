package localwarm

import (
	"errors"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// preSendError marks a failure that provably occurred BEFORE any part of the
// op's command was transmitted to the runspace — i.e. only the CreatePipeline
// SendCommand packet (which carries no script) failed. It is the ONLY class the
// warm engine may retry transparently, because a retry re-runs the op and AD
// writes are non-idempotent.
//
// Deliberately narrow: a failure once Invoke has run is NOT wrapped in this
// type, even though Invoke's send often fails only because the shell is dead.
// Invoke serializes the script and sends the CREATE_PIPELINE message — the
// actual command — so an error there is not provably pre-execution, and the
// op may already have reached AD. That mirrors transport/psrp's classifier,
// which for the same reason refuses to retry a possibly-sent script.
type preSendError struct{ err error }

func (e *preSendError) Error() string { return e.err.Error() }
func (e *preSendError) Unwrap() error { return e.err }

// localClassifier injects the local+warm error detection into the warm pool's
// retry policy. The pool owns the policy (one retry, dead-shell only); this
// owns the detection.
type localClassifier struct{}

// MapError classifies every local failure as KindTransport. A local warm
// failure is a channel/process failure, never a "provably did not execute"
// transient, so it is never retried on the KindTransient path — only a
// pre-send dead shell (below) is retried, and that is the DeadShell signal.
func (localClassifier) MapError(err error) error {
	return &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "localwarm", Err: err}
}

// DeadShell reports whether err is a confirmed pre-send failure — the only
// class safe to retry transparently. errors.As unwraps to any depth.
func (localClassifier) DeadShell(err error) bool {
	var pse *preSendError
	return errors.As(err, &pse)
}
