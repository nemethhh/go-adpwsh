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
func TestScriptsAvoidPowerShell7Constructs(t *testing.T) {
	banned := []struct {
		what string
		re   *regexp.Regexp
	}{
		{"null-conditional access (?. or ?[)", regexp.MustCompile(`\?\.|\?\[`)},
		{"null-coalescing (??)", regexp.MustCompile(`\?\?`)},
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
