package adscript

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWrapFullPayloadSeedsSetInAndPreload(t *testing.T) {
	payload := []byte(`{"identity":"krbtgt"}`)
	script := "Get-ADUser @common"
	out := WrapFullPayload(script, payload)

	b64 := base64.StdEncoding.EncodeToString(payload)
	if !strings.Contains(out, "[Console]::SetIn(") {
		t.Error("missing [Console]::SetIn seeding")
	}
	if !strings.Contains(out, b64) {
		t.Error("payload base64 not embedded")
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), script) {
		t.Errorf("op script must come last; got tail %q", out[len(out)-40:])
	}
	// payload must NOT appear as un-encoded script text (no interpolation)
	if strings.Contains(out, `"identity":"krbtgt"`) {
		t.Error("raw payload leaked into script text")
	}
}
