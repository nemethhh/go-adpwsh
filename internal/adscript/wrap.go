package adscript

import (
	"encoding/base64"
	"strings"
)

// preload works around an empty [AppContext]::BaseDirectory in a PS7 remote or
// out-of-proc runspace, which otherwise breaks the AD module's lazily-loaded
// WCF dependency. $PSHOME is correct in the runspace, so LoadFrom by full path
// succeeds; it is best-effort so it is a harmless no-op where the runtime
// already resolves it.
const preload = `try { [System.Reflection.Assembly]::LoadFrom("$PSHOME\System.ServiceModel.NetFramingBase.dll") | Out-Null } catch {}`

// WrapFullPayload seeds the op's JSON payload into [Console]::In (so the
// unchanged preamble's [Console]::In.ReadToEnd() returns the JSON) plus the WCF
// preload, then appends the op script. It is the full-language delivery path,
// shared by every transport that runs full-language PowerShell: the winrm full
// mode and the local/ssh warm executors. The constrained-language variant
// (a single-quoted $__adPayload literal) has no [Console]/.NET calls available
// and stays in transport/psrp.
func WrapFullPayload(script string, payload []byte) string {
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
