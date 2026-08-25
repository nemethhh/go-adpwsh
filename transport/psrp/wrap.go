package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman"
)

// preload works around an empty [AppContext]::BaseDirectory in a PS7 remote
// runspace, which otherwise breaks the AD module's lazily-loaded WCF dependency.
// $PSHOME is correct in the runspace, so LoadFrom by full path succeeds; it is
// best-effort so it is a harmless no-op where the runtime already resolves it.
const preload = `try { [System.Reflection.Assembly]::LoadFrom("$PSHOME\System.ServiceModel.NetFramingBase.dll") | Out-Null } catch {}`

// buildWrapper prepends payload delivery (base64 -> [Console]::SetIn, so the
// script's [Console]::In.ReadToEnd() returns the JSON) and the WCF preload,
// then the original script. Base64 keeps the payload injection-safe.
func buildWrapper(script string, payload []byte) string {
	b64 := base64.StdEncoding.EncodeToString(payload)
	var b strings.Builder
	b.WriteString(`[Console]::SetIn([System.IO.StringReader]::new([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('`)
	b.WriteString(b64)
	b.WriteString("'))))\n")
	b.WriteString(preload)
	b.WriteString("\n")
	b.WriteString(script)
	return b.String()
}

// joinObjects renders go-psrp's deserialized output stream back to the raw text
// the go-adpwsh envelope parser expects: one element per line.
func joinObjects(objs []interface{}) string {
	if len(objs) == 0 {
		return ""
	}
	parts := make([]string, len(objs))
	for i, o := range objs {
		parts[i] = fmt.Sprintf("%v", o)
	}
	return strings.Join(parts, "\n")
}

func exitCode(hadErrors bool) int {
	if hadErrors {
		return 1
	}
	return 0
}

// mapExecuteError classifies a genuine transport failure. Retryable pool/queue
// conditions and context cancellation are KindTransient; anything else is a
// dial/auth/protocol failure and is KindTransport.
func mapExecuteError(err error) error {
	switch {
	case errors.Is(err, psrp.ErrQueueFull),
		errors.Is(err, psrp.ErrCircuitOpen),
		errors.Is(err, psrp.ErrNotConnected),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "Run", Err: err}
	default:
		return &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "Run", Err: err}
	}
}

// deadShellRetryExhaustedMessage is startPipeline's own literal (client.go,
// vendored go-psrp) when every one of its 3 attempts to prepare/invoke a
// pipeline fails with a bare HTTP 401. That 401 is the one case a shell-death
// signature can arrive with genuinely no SOAP body to type-check: WSMan never
// gets to render a Fault because the request is rejected at the HTTP auth
// layer first. There is nothing to wrap a sentinel around, so this is
// deliberately the only string match left in isDeadShellFailure — everything
// else that *can* carry a body is checked via wsman.Fault below instead.
// Earlier revisions of this classifier also matched "prepare pipeline: " by
// prefix, which was wrong: for the WSMan backend this repo always configures,
// PreparePipeline (powershell/runspace.go) sends the script itself in the
// same synchronous round trip that "prepare pipeline: " wraps — Invoke is
// then a no-op (SkipInvokeSend) — so a "prepare pipeline: " failure is not
// reliably pre-execution; a deadline or reset there can follow a script that
// already reached the server. Re-verify this reasoning against
// powershell/runspace.go and client/client.go's startPipeline on any go-psrp
// version bump.
const deadShellRetryExhaustedMessage = "failed to start pipeline after retries due to transport error"

// isDeadShellFailure reports whether err is the class of failure produced
// when the shell behind a pooled conn no longer exists — idle-timeout reaped,
// or the host's WinRM service was restarted. go-psrp's own Client keeps
// believing it is connected in this situation (nothing resets its internal
// `connected` flag; see conn.invalidate in psrp.go), so every attempt to
// start a pipeline in that dead shell fails before the script runs. Run
// treats this, and only this, as safe to retry once against a freshly
// rebuilt client.
//
// Two independent checks, deliberately asymmetric:
//   - A definitive server-side "no such shell" WSMan Fault (IsShellNotFound)
//     proves nothing could have executed: the request was rejected before
//     WSMan ever routed it to a runspace. errors.As reaches it regardless of
//     wrapping depth — the fault survives every %w in the chain from
//     startPipeline's "prepare pipeline: " down through PreparePipeline's
//     "create wsman command: ", Command's "create command: ", and
//     sendEnvelope's "wsman: %w" (see wsman/client.go, wsman/errors.go).
//   - The bare HTTP-401 retry-exhausted literal, matched by string because a
//     401 has no SOAP body to type-check — this is the one first-party
//     message with no wrapped error underneath it to misclassify.
//
// invoke pipeline: %w is deliberately not handled by either check: for the
// WSMan backend, PreparePipeline already sends the script and calls
// SkipInvokeSend (powershell/runspace.go), so psrpPipeline.Invoke never sends
// anything and this error path is unreachable on this transport today. It
// would need revisiting only if a different backend (e.g. HvSocket) were ever
// wired into this package.
func isDeadShellFailure(err error) bool {
	if err == nil {
		return false
	}
	var fault *wsman.Fault
	if errors.As(err, &fault) && fault.IsShellNotFound() {
		return true
	}
	return strings.Contains(err.Error(), deadShellRetryExhaustedMessage)
}
