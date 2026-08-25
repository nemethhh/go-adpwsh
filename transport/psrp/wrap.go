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

// preparePipelineWrapMarker is the literal wrap text startPipeline
// (client/client.go) adds around a PreparePipeline/Command failure —
// "prepare pipeline: %w". It is the only available signal (no sentinel
// exists) that a failure originated in the prepare/command path rather than
// in output streaming; see isDeadShellFailure for why that distinction is
// required, not optional.
const preparePipelineWrapMarker = "prepare pipeline: "

// isDeadShellFailure reports whether err is the class of failure produced
// when the shell behind a pooled conn no longer exists — idle-timeout reaped,
// or the host's WinRM service was restarted. go-psrp's own Client keeps
// believing it is connected in this situation (nothing resets its internal
// `connected` flag; see conn.invalidate in psrp.go), so every attempt to
// start a pipeline in that dead shell fails before the script runs. Run
// treats this, and only this, as safe to retry once against a freshly
// rebuilt client.
//
// Two checks, and the fault one is a conjunction, not a single signal:
//
//   - The bare HTTP-401 retry-exhausted literal, matched by string because a
//     401 has no SOAP body to type-check — this is the one first-party
//     message with no wrapped error underneath it to misclassify. Reachable
//     only after 3 consecutive prepare-path 401s, so zero executions occurred.
//
//   - A "shell not found" WSMan Fault (IsShellNotFound), AND independent
//     evidence it came from the prepare/command path, not output streaming.
//     The fault alone is not enough: the exact same fault, with
//     IsShellNotFound()==true, also arrives from Receive — WSManTransport.Read
//     -> wsman.Client.Receive ("receive: %w") -> WSManTransport.Read's own
//     "wsman receive: %w" -> runPipelineReceive's io.ReadFull failure
//     ("read fragment header: %w") -> pl.Fail, returned verbatim by Wait() —
//     a path that only runs AFTER Invoke succeeded. Receive uses the same
//     ShellId selector as the prepare path, so a shell destroyed *mid-
//     execution* (a WinRM bounce during a long replication wait, say)
//     produces an indistinguishable fault. Retrying that resends the script
//     after the original may already have completed its AD write.
//
//     So the fault only counts alongside preparePipelineWrapMarker being
//     present in the error text — the one thing that path adds and the
//     Receive path never does (it wraps with "read fragment header: ",
//     "wsman receive: ", "receive: " instead). errors.As still reaches the
//     fault through arbitrary wrapping depth (startPipeline's
//     "prepare pipeline: " -> PreparePipeline's "create wsman command: " ->
//     Command's "create command: " -> sendEnvelope's "wsman: %w"; see
//     wsman/client.go, wsman/errors.go), but the marker check is what tells
//     apart which call site produced it.
//
//     This is deliberately a conjunction, not a fallback: if a future
//     go-psrp version rewords either the fault's own text or this wrap
//     marker, the conjunction simply stops matching and Run stops retrying
//     — it fails closed (a surfaced error), never open (a silent retry).
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
	if strings.Contains(err.Error(), deadShellRetryExhaustedMessage) {
		return true
	}
	var fault *wsman.Fault
	return errors.As(err, &fault) && fault.IsShellNotFound() &&
		strings.Contains(err.Error(), preparePipelineWrapMarker)
}
