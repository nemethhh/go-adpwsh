package adscript

import (
	"strings"
	"testing"
)

// The shared preamble must be mode-aware where ConstrainedLanguage actually
// requires it: the payload arrives as $__adPayload (never [Console]::In under a
// constrained endpoint) and Import-Module is guarded by Get-Module (the cmdlet
// is not visible on a restricted endpoint, but the module is pre-imported). The
// credential is built with the [PSCredential] constructor unconditionally:
// PSCredential/SecureString are ConstrainedLanguage "core" types, so the
// constructor runs in both full and constrained sessions (lab-verified) — no
// endpoint helper function. See the psrp-constrained-language design doc.
func TestPreambleModeAware(t *testing.T) {
	s, err := Script(OpOURead)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$__adPayload",               // CLM-safe payload delivery (no [Console]::SetIn)
		"Get-Module ActiveDirectory", // Import-Module guard for restricted endpoints
		// The stock credential constructor — works in full AND constrained mode.
		"[System.Management.Automation.PSCredential]::new",
		"ConvertTo-SecureString",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("preamble missing %q", want)
		}
	}
	// The [Console] fallback stays for ssh/local/full (real stdin); constrained
	// mode sets $__adPayload so it is never reached there.
	if !strings.Contains(s, "[Console]::In.ReadToEnd()") {
		t.Errorf("preamble dropped the [Console]::In full/ssh/local fallback")
	}
	// The endpoint helper must be gone — the constructor works in CLM directly.
	if strings.Contains(s, "New-TfCredential") {
		t.Errorf("preamble still references New-TfCredential; the [PSCredential] constructor is CLM-safe on its own")
	}
}
