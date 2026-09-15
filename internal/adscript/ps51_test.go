package adscript

import (
	"regexp"
	"testing"
)

// Windows PowerShell 5.1 is the baseline engine: a management host must not need
// PowerShell 7 installed. Every construct below is 6+ or 7+ only, so a script
// using one compiles fine here and then fails on a 5.1 endpoint at run time.
// This is the static gate; the executing gate is the dual-engine acceptance run
// on the lab, because the in-memory fake never runs PowerShell at all.
//
// The guard covers the ADWS dialect only, and does so by construction: it walks
// Ops() through Script(), which is the ADWS set. The psopenad dialect is
// deliberately out of scope - it requires PowerShell 7.4 and uses 7-only
// constructs on purpose. Do not widen this to ScriptFor without splitting the
// banned list per dialect. TestPSOpenADDialectIsExemptFromThe51Guard below
// asserts that the exemption is real rather than vacuous.
func TestScriptsAvoidPowerShell7Constructs(t *testing.T) {
	banned := []struct {
		what string
		re   *regexp.Regexp
	}{
		{"null-conditional access (?. or ?[)", regexp.MustCompile(`\?\.|\?\[`)},
		{"null-coalescing (??)", regexp.MustCompile(`\?\?`)},
		{"ternary (cond ? a : b)", regexp.MustCompile(`\s\?\s`)},
		{"ConvertFrom-Json -AsHashtable", regexp.MustCompile(`(?i)ConvertFrom-Json[^\n]*-AsHashtable`)},
		{"ForEach-Object -Parallel", regexp.MustCompile(`(?i)-Parallel\b`)},
		{"PowerShell class declaration", regexp.MustCompile(`(?m)^\s*class\s+\w`)},
	}
	check := func(label, body string) {
		for _, b := range banned {
			if hit := b.re.FindString(body); hit != "" {
				t.Errorf("%s uses %s (found %q): not available in Windows PowerShell 5.1", label, b.what, hit)
			}
		}
	}
	for _, op := range Ops() {
		s, err := Script(op)
		if err != nil {
			t.Fatalf("Script(%q): %v", op, err)
		}
		check("op "+op, s)
	}
	for _, tool := range Tools() {
		s, err := ToolScript(tool)
		if err != nil {
			t.Fatalf("ToolScript(%q): %v", tool, err)
		}
		check("tool "+tool, s)
	}
	// The ACL endpoint helpers install as -FunctionDefinitions on a
	// ConstrainedLanguage endpoint and run FullLanguage there, but the host
	// itself is still Windows PowerShell 5.1: a 6+/7+-only construct in this
	// file would fail to parse on the endpoint at registration time, before
	// ConstrainedLanguage mode is even relevant.
	check("endpoint/acl_helpers.ps1", ACLEndpointHelpers())
}

// The converter's scalar short-circuit is load-bearing and easy to delete by
// accident: in Windows PowerShell a string satisfies -is [PSCustomObject],
// because the accelerator resolves to PSObject, which wraps everything. Without
// the guard every string in the payload is walked as an object and becomes a
// hashtable of its members, which surfaces as "One or more properties are
// invalid. Parameter name: System.Collections.Hashtable" from the AD cmdlets.
func TestPayloadConverterShortCircuitsScalars(t *testing.T) {
	s, err := Script(OpOURead)
	if err != nil {
		t.Fatalf("Script: %v", err)
	}
	for _, want := range []string{
		"function ConvertTo-AdHashtable",
		"if ($o -is [string] -or $o -is [System.ValueType]) { return $o }",
		"[System.Management.Automation.PSCustomObject]",
		"function Get-AdPropValue",
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(s) {
			t.Errorf("composed script is missing %q", want)
		}
	}
}

// The exemption above is only meaningful while the psopenad dialect actually
// exists and actually uses a construct the guard bans. If this test starts
// failing, either the dialect was deleted or it was rewritten to 5.1
// compatibility - in both cases the exemption comment above is now a lie.
func TestPSOpenADDialectIsExemptFromThe51Guard(t *testing.T) {
	pre, err := files.ReadFile("ops_psopenad/preamble.ps1")
	if err != nil {
		t.Fatalf("the psopenad dialect must exist for its guard exemption to mean anything: %v", err)
	}
	if !regexp.MustCompile(`(?i)ConvertFrom-Json[^\n]*-AsHashtable`).Match(pre) {
		t.Error("the psopenad preamble no longer uses a PowerShell 7-only construct; " +
			"the 5.1 guard exemption is now unnecessary and should be removed")
	}
}
