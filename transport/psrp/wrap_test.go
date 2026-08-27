package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman"
)

func TestBuildWrapperDeliversPayloadAndPreload(t *testing.T) {
	w := buildWrapper("Get-ADDomain", []byte(`{"server":null}`), false)
	// payload arrives as base64 inside a SetIn call
	if !strings.Contains(w, base64.StdEncoding.EncodeToString([]byte(`{"server":null}`))) {
		t.Error("wrapper missing base64 payload")
	}
	if !strings.Contains(w, "[Console]::SetIn(") {
		t.Error("wrapper missing SetIn")
	}
	if !strings.Contains(w, "System.ServiceModel.NetFramingBase.dll") {
		t.Error("wrapper missing WCF preload")
	}
	if !strings.HasSuffix(w, "Get-ADDomain") {
		t.Error("wrapper must end with the original script")
	}
	// SetIn must precede the script
	if strings.Index(w, "SetIn") > strings.Index(w, "Get-ADDomain") {
		t.Error("SetIn must come before the script")
	}
}

func TestBuildWrapperConstrained(t *testing.T) {
	w := buildWrapper("SCRIPT", []byte(`{"a":"it's"}`), true)
	if strings.Contains(w, "[Console]::SetIn") || strings.Contains(w, "LoadFrom") {
		t.Errorf("constrained wrapper must not use [Console]::SetIn or LoadFrom:\n%s", w)
	}
	if !strings.Contains(w, `$__adPayload = '{"a":"it''s"}'`) {
		t.Errorf("constrained wrapper must set $__adPayload with '' escaped:\n%s", w)
	}
	if !strings.HasSuffix(w, "SCRIPT") {
		t.Errorf("script must follow the payload assignment:\n%s", w)
	}
}

func TestBuildWrapperFullUnchanged(t *testing.T) {
	w := buildWrapper("SCRIPT", []byte(`{}`), false)
	if !strings.Contains(w, "[Console]::SetIn") {
		t.Errorf("full wrapper must keep [Console]::SetIn delivery:\n%s", w)
	}
}

func TestJoinObjectsAndExitCode(t *testing.T) {
	if got := joinObjects([]interface{}{"a", "b", "c"}); got != "a\nb\nc" {
		t.Errorf("joinObjects = %q", got)
	}
	if got := joinObjects(nil); got != "" {
		t.Errorf("joinObjects(nil) = %q, want empty", got)
	}
	if exitCode(false) != 0 || exitCode(true) != 1 {
		t.Error("exitCode mapping wrong")
	}
}

// TestMapExecuteError pins mapExecuteError's retry/no-retry boundary.
// KindTransient must mean "provably nothing executed": the three go-psrp
// sentinels satisfy that by construction (they short-circuit on a semaphore,
// circuit-breaker or connection-state check before anything is sent), so they
// stay KindTransient. A context error does not satisfy that bar — in the
// WSMan backend, PreparePipeline is the network send of the script itself,
// and a deadline or cancellation can fire while awaiting the response, i.e.
// after the script already reached the server — so both context.Canceled and
// context.DeadlineExceeded, bare or wrapped to any depth, must fall through
// to KindTransport, which core.exec never retries.
func TestMapExecuteError(t *testing.T) {
	var e *adpwsh.Error

	transientCases := []struct {
		name string
		err  error
	}{
		{"ErrQueueFull", psrp.ErrQueueFull},
		{"ErrCircuitOpen", psrp.ErrCircuitOpen},
		{"ErrNotConnected", psrp.ErrNotConnected},
	}
	for _, tc := range transientCases {
		if !errors.As(mapExecuteError(tc.err), &e) || e.Kind != adpwsh.KindTransient {
			t.Errorf("%s should map to KindTransient (pre-send sentinel; provably nothing executed)", tc.name)
		}
	}

	nonRetryableCases := []struct {
		name string
		err  error
	}{
		{"bare context.DeadlineExceeded", context.DeadlineExceeded},
		{"bare context.Canceled", context.Canceled},
		// The shape that actually occurs: startPipeline wraps a deadline hit
		// mid-PreparePipeline as "prepare pipeline: %w". errors.Is unwraps to
		// any depth, so this must classify the same as the bare error.
		{"wrapped deadline (prepare pipeline: %w)", fmt.Errorf("prepare pipeline: %w", context.DeadlineExceeded)},
	}
	for _, tc := range nonRetryableCases {
		if !errors.As(mapExecuteError(tc.err), &e) || e.Kind != adpwsh.KindTransport {
			t.Errorf("%s should map to KindTransport (not provably pre-execution; must not retry)", tc.name)
		}
	}

	if !errors.As(mapExecuteError(errors.New("dial tcp: refused")), &e) || e.Kind != adpwsh.KindTransport {
		t.Error("unknown should map to KindTransport")
	}
}

// TestMapExecuteErrorNeverRetriesContextError is a standalone guard for the
// invariant this fix restores: a context error must never again become
// retryable. It exists separately from TestMapExecuteError so a future
// change that reintroduces context.Canceled/context.DeadlineExceeded into
// the KindTransient branch fails a test whose name says exactly what broke.
func TestMapExecuteErrorNeverRetriesContextError(t *testing.T) {
	for _, ctxErr := range []error{context.Canceled, context.DeadlineExceeded} {
		var e *adpwsh.Error
		if !errors.As(mapExecuteError(ctxErr), &e) {
			t.Fatalf("mapExecuteError(%v) did not produce an *adpwsh.Error", ctxErr)
		}
		if e.Kind == adpwsh.KindTransient {
			t.Errorf("mapExecuteError(%v) = KindTransient; a context error is not provably pre-execution and must never be retryable", ctxErr)
		}
	}
}

// TestIsDeadShellFailure pins the exact boundary Run uses to decide whether a
// KindTransport Execute failure is safe to retry: the bare HTTP-401
// retry-exhausted literal, or a typed wsman.Fault confirming the server has
// no such shell AND independent evidence it came from the prepare/command
// path rather than output streaming. The fault check is deliberately a
// conjunction, not the fault alone: the identical fault, with
// IsShellNotFound()==true, also arrives from the Receive path (reached only
// after Invoke already succeeded), so isDeadShellFailure must require the
// "prepare pipeline: " wrap marker alongside the fault, or it would retry an
// operation that may have already reached Active Directory. Everything else
// — including a "prepare pipeline: " failure with no fault underneath it
// (e.g. a plain context deadline or connection reset), and a genuine
// shell-not-found fault wrapped the way the Receive path wraps it — must
// come back false.
func TestIsDeadShellFailure(t *testing.T) {
	shellNotFound := &wsman.Fault{
		Subcode: "w:InvalidSelectors",
		Reason:  "The WS-Management service cannot process the request because the shell was not found.",
	}
	accessDenied := &wsman.Fault{Subcode: "w:AccessDenied", WSManCode: 5}
	// shellNotFoundSpoofedReason is a genuine shell-not-found fault whose
	// server-supplied Reason text happens to contain the literal
	// "prepare pipeline: " — a DC (or anything reflecting attacker-supplied
	// text into a fault Reason/Subcode) could construct this. It exists to
	// prove the marker check is a prefix check, not a substring search: the
	// marker must be the outermost wrap, not text the server can plant
	// anywhere in the message to forge the origin signal.
	shellNotFoundSpoofedReason := &wsman.Fault{
		Subcode: "w:InvalidSelectors",
		Reason:  "The WS-Management service cannot process the request because the shell was not found. Client reported: prepare pipeline: forged marker",
	}

	// wrapLikePreparePath mirrors the real chain a WSMan fault travels
	// through when PreparePipeline/Command fails: sendEnvelope's "wsman: %w"
	// -> Command's "create command: %w" -> PreparePipeline's "create wsman
	// command: %w" -> startPipeline's "prepare pipeline: %w". This runs
	// before Invoke, so nothing has reached the server yet.
	wrapLikePreparePath := func(cause error) error {
		return fmt.Errorf("prepare pipeline: %w", fmt.Errorf("create wsman command: %w", fmt.Errorf("create command: %w", fmt.Errorf("wsman: %w", cause))))
	}

	// wrapLikeReceivePath mirrors the real chain the exact same fault travels
	// through when it instead arrives from output streaming, which only runs
	// AFTER Invoke succeeded: wsman.Client.Receive's "receive: %w" ->
	// WSManTransport.Read's "wsman receive: %w" -> runPipelineReceive's
	// io.ReadFull failure, "read fragment header: %w" (client/client.go).
	// This never contains "prepare pipeline: " anywhere — that is the whole
	// point of requiring the marker.
	wrapLikeReceivePath := func(cause error) error {
		return fmt.Errorf("read fragment header: %w", fmt.Errorf("wsman receive: %w", fmt.Errorf("receive: %w", fmt.Errorf("wsman: %w", cause))))
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"retry-exhausted (the exact lab failure, no SOAP body to type-check)", errors.New(deadShellRetryExhaustedMessage), true},
		{"shell-not-found fault from the prepare path — must retry", wrapLikePreparePath(shellNotFound), true},
		{"shell-not-found fault from the RECEIVE path (post-Invoke) — must NOT retry", wrapLikeReceivePath(shellNotFound), false},
		{"shell-not-found fault from the RECEIVE path whose Reason contains the marker text — must NOT retry (HasPrefix, not Contains)", wrapLikeReceivePath(shellNotFoundSpoofedReason), false},
		{"access-denied fault from the prepare path: a real fault, but not a dead shell", wrapLikePreparePath(accessDenied), false},
		{"prepare pipeline with no fault underneath (deadline) — must NOT retry", wrapLikePreparePath(context.DeadlineExceeded), false},
		{"prepare pipeline with no fault underneath (connection reset) — must NOT retry", wrapLikePreparePath(errors.New("read tcp 10.0.0.1:1234: connection reset by peer")), false},
		{"create pipeline (local, no longer specially recognized)", errors.New("create pipeline: pool is broken"), false},
		{"get create pipeline data (local, no longer specially recognized)", errors.New("get create pipeline data: serialize: boom"), false},
		{"invoke pipeline (unreachable on the WSMan backend; excluded on purpose)", errors.New("invoke pipeline: dial tcp: connection refused"), false},
		{"post-invoke stream failure", errors.New("read output stream: unexpected EOF"), false},
		{"unrelated transport error", errors.New("dial tcp: connection refused"), false},
	}
	for _, tc := range cases {
		if got := isDeadShellFailure(tc.err); got != tc.want {
			t.Errorf("%s: isDeadShellFailure = %v, want %v", tc.name, got, tc.want)
		}
	}
}
