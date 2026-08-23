package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
)

// preload works around an empty [AppContext]::BaseDirectory in a PS7 remote
// runspace, which otherwise breaks the AD module's lazily-loaded WCF dependency.
// $PSHOME is correct in the runspace, so LoadFrom by full path succeeds; it is
// best-effort so it is a harmless no-op where the runtime already resolves it.
const preload = `try { [System.Reflection.Assembly]::LoadFrom("$PSHOME\System.ServiceModel.NetFramingBase.dll") | Out-Null } catch {}`

// decodeEncodedCommand reverses go-adpwsh's -EncodedCommand encoding
// (UTF-16LE then base64) back to the original script text.
func decodeEncodedCommand(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("psrp: decode EncodedCommand base64: %w", err)
	}
	if len(raw)%2 != 0 {
		return "", errors.New("psrp: EncodedCommand is not valid UTF-16LE (odd byte count)")
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u)), nil
}

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
