package winrm

import (
	"errors"
	"fmt"
	"strings"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	psrp "github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrp/wsman"
)

// buildWrapper prepends payload delivery to the composed script. In full mode
// it delegates to adscript.WrapFullPayload ([Console]::SetIn so the script's
// [Console]::In.ReadToEnd() returns the JSON, plus the WCF preload) — the same
// path the local/ssh warm executors use. In constrained mode neither is
// available (both are .NET calls a ConstrainedLanguage endpoint rejects), so
// the payload is delivered as an injection-safe single-quoted literal the
// preamble reads from $__adPayload; single quotes are doubled, which is
// complete escaping for a single-quoted PowerShell string, and json.Marshal
// emits single-line JSON.
func buildWrapper(script string, payload []byte, constrained bool) string {
	if constrained {
		lit := strings.ReplaceAll(string(payload), "'", "''")
		return "$__adPayload = '" + lit + "'\n" + script
	}
	return adscript.WrapFullPayload(script, payload)
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

// mapExecuteError classifies a genuine transport failure. KindTransient is a
// promise to core.exec, not a severity label: it means the operation
// provably did not execute, so re-issuing the identical script and payload
// cannot duplicate a side effect (see Kind.retryable in errors.go). Only the
// three go-psrp sentinels below meet that bar — each short-circuits on a
// semaphore, circuit-breaker or connection-state check before anything is
// sent, by construction, every time. Everything else, including a context
// error, is KindTransport and is never retried by core.exec.
//
// context.Canceled and context.DeadlineExceeded deliberately do NOT join the
// sentinels, even though a caller-side timeout sounds exactly like the kind
// of thing worth retrying. In the WSMan backend this package always
// configures, PreparePipeline is the network send of the CreatePipeline
// payload — the script itself — and SkipInvokeSend() then makes Invoke a
// no-op. A deadline or cancellation observed while awaiting that response is
// indistinguishable from one observed before the send: the script may
// already have reached the server. Classifying it as transient risked
// executing a non-idempotent operation — or a create — more than once (the
// bug this comment documents). The sentinels are provably pre-send; a
// context error is not provably anything, so it fails closed to
// KindTransport. errors.Is unwraps to any depth, so a wrapped context error
// (e.g. startPipeline's "prepare pipeline: %w") classifies the same as a
// bare one.
//
// A caller-side cancellation loses nothing by this asymmetry: core.backoff
// already checks the caller's own ctx.Done() and aborts the retry loop the
// moment it fires, independent of how this function classifies the error.
// The case this guards is a deadline or reset arising from the transport's
// own timeout, or from inside go-psrp's HTTP client, while the caller's
// context is still alive — there, the Kind returned here is the only thing
// standing between one execution and up to Retry.MaxAttempts of them.
//
// This Kind answers only "is it safe to retry?" (no, for a context error).
// It deliberately does not answer "is the shell dead?" — warm's isCallerTimeout
// (internal/warm) is what the pool's Run consults separately for that second
// question.
func mapExecuteError(err error) error {
	switch {
	case errors.Is(err, psrp.ErrQueueFull),
		errors.Is(err, psrp.ErrCircuitOpen),
		errors.Is(err, psrp.ErrNotConnected):
		return &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "Run", Err: err}
	default:
		// Known false negative, accepted deliberately: a timeout while queued
		// for a concurrency slot ("pool busy: context deadline exceeded")
		// provably never reached the network, so it would be safe to retry.
		// It lands here anyway, because the only thing distinguishing it from a
		// timeout awaiting a response is text we would have to match, and the
		// cost of guessing wrong is a duplicated write. Failing closed on a
		// retryable case loses one retry; failing open loses data.
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
// `connected` flag; see conn.invalidate in internal/warm), so every attempt to
// start a pipeline in that dead shell fails before the script runs. The pool's
// Run treats this, and only this, as safe to retry once against a freshly
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
//     So the fault only counts alongside preparePipelineWrapMarker being a
//     PREFIX of the error text — the one thing that path adds and the
//     Receive path never does (it wraps with "read fragment header: ",
//     "wsman receive: ", "receive: " instead). errors.As still reaches the
//     fault through arbitrary wrapping depth (startPipeline's
//     "prepare pipeline: " -> PreparePipeline's "create wsman command: " ->
//     Command's "create command: " -> sendEnvelope's "wsman: %w"; see
//     wsman/client.go, wsman/errors.go), but the marker check is what tells
//     apart which call site produced it. HasPrefix, not Contains: nothing
//     wraps above startPipeline, so in the legitimate case the marker is
//     always the outermost, first token of the string. Contains would also
//     match server-supplied text — the fault's own Reason/Subcode from the
//     DC — so a Receive-path fault whose message happened to contain the
//     literal "prepare pipeline: " would forge the origin signal and defeat
//     the whole point of requiring it.
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
		strings.HasPrefix(err.Error(), preparePipelineWrapMarker)
}
