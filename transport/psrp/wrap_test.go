package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman"
)

// encode mimics how go-adpwsh produces an -EncodedCommand: UTF-16LE then base64.
func encode(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestBuildWrapperDeliversPayloadAndPreload(t *testing.T) {
	w := buildWrapper("Get-ADDomain", []byte(`{"server":null}`))
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

func TestMapExecuteError(t *testing.T) {
	var e *adpwsh.Error
	if !errors.As(mapExecuteError(psrp.ErrQueueFull), &e) || e.Kind != adpwsh.KindTransient {
		t.Error("ErrQueueFull should map to KindTransient")
	}
	if !errors.As(mapExecuteError(context.DeadlineExceeded), &e) || e.Kind != adpwsh.KindTransient {
		t.Error("context deadline should map to KindTransient")
	}
	if !errors.As(mapExecuteError(errors.New("dial tcp: refused")), &e) || e.Kind != adpwsh.KindTransport {
		t.Error("unknown should map to KindTransport")
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
