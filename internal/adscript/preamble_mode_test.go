package adscript

import (
	"strings"
	"testing"
)

// The shared preamble must be mode-aware: constrained endpoints deliver the
// payload as $__adPayload and build credentials via New-TfCredential, while
// full/ssh/local keep [Console]::In and [PSCredential]::new. See the
// psrp-constrained-language design doc.
func TestPreambleModeAware(t *testing.T) {
	s, err := Script(OpOURead)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$__adPayload",               // constrained input path
		"New-TfCredential",           // constrained credential path
		"Get-Module ActiveDirectory", // Import-Module guard
	} {
		if !strings.Contains(s, want) {
			t.Errorf("preamble missing %q", want)
		}
	}
	// The full-mode fallbacks must remain for ssh/local/full.
	for _, want := range []string{
		"[Console]::In.ReadToEnd()",
		"[System.Management.Automation.PSCredential]::new",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("preamble dropped full-mode fallback %q", want)
		}
	}
}
