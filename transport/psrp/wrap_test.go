package psrp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	adpwsh "github.com/nemethhh/go-adpwsh"
	psrp "github.com/smnsjas/go-psrp/client"
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
