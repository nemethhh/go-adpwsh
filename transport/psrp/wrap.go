package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
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

// deadShellFailurePrefixes are the exact fmt.Errorf-wrapped messages go-psrp's
// Client produces when a pipeline could not be *started* at all — i.e.
// strictly before the script had any chance to run on the server. Sourced
// from the vendored go-psrp (client/client.go's startPipeline): "create
// pipeline", "get create pipeline data" and "prepare pipeline" all return
// before psrpPipeline.Invoke is ever attempted, and the fourth string is
// startPipeline's own message when every one of its 3 attempts fails before
// a successful Invoke. Deliberately excludes "invoke pipeline: " and anything
// surfacing from output streaming (pipeline.Wait, reached only after Invoke
// succeeds): a failure there can mean the server already accepted and started
// running the script, and retrying that risks re-running a write that already
// reached Active Directory. Re-verify these strings against client.go on any
// go-psrp version bump.
var deadShellFailurePrefixes = []string{
	"create pipeline: ",
	"get create pipeline data: ",
	"prepare pipeline: ",
	"failed to start pipeline after retries due to transport error",
}

// isDeadShellFailure reports whether err is the class of failure produced
// when the shell behind a pooled conn no longer exists — idle-timeout reaped,
// or the host's WinRM service was restarted. go-psrp's own Client keeps
// believing it is connected in this situation (nothing resets its internal
// `connected` flag; see conn.invalidate in psrp.go), so every attempt to
// start a pipeline in that dead shell fails before the script runs. Run
// treats this, and only this, as safe to retry once against a freshly
// rebuilt client.
func isDeadShellFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, p := range deadShellFailurePrefixes {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
