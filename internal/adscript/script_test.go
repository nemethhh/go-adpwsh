package adscript

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden script files")

// The script text is constant, so golden files diff cleanly and any change to
// what actually runs on the jump box is a reviewable diff.
func TestScriptGolden(t *testing.T) {
	for _, op := range Ops() {
		t.Run(op, func(t *testing.T) {
			got, err := Script(op)
			if err != nil {
				t.Fatalf("Script(%q): %v", op, err)
			}
			path := filepath.Join("testdata", "golden", op+".ps1")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run: go test ./internal/adscript -run TestScriptGolden -update)", err)
			}
			if got != string(want) {
				t.Errorf("script for %q changed; diff %s against the new output", op, path)
			}
		})
	}
}

func TestScriptInvariants(t *testing.T) {
	for _, op := range Ops() {
		s, err := Script(op)
		if err != nil {
			t.Fatalf("Script(%q): %v", op, err)
		}
		for _, want := range []string{
			"$ErrorActionPreference = 'Stop'",
			"Import-Module ActiveDirectory -ErrorAction Stop",
			"ConvertFrom-Json -AsHashtable",
			"<<<TFAD:BEGIN>>>",
			"<<<TFAD:END>>>",
			"-Depth 6 -Compress",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("op %q: composed script is missing %q", op, want)
			}
		}
	}
}

// Script takes an op name from a closed set, which is what makes formatting a
// value into script text impossible rather than merely discouraged.
func TestScriptRejectsUnknownOp(t *testing.T) {
	if _, err := Script("rm -rf /"); err == nil {
		t.Fatal("Script must reject an unknown op")
	}
}

func TestScriptIsStable(t *testing.T) {
	a, _ := Script(OpUserCreate)
	b, _ := Script(OpUserCreate)
	if a != b {
		t.Error("Script must return identical text on every call")
	}
}

// The tool set is separate from the op set on purpose. A schema export is
// build-time tooling — nothing in an apply path queries the schema — so it does
// not earn a place among the operations the library performs, and no caller of
// Script can reach it.
func TestToolsAreNotOps(t *testing.T) {
	for _, tool := range Tools() {
		if _, err := Script(tool); err == nil {
			t.Errorf("Script(%q) must fail: tools are not ops", tool)
		}
	}
	for _, op := range Ops() {
		if _, err := ToolScript(op); err == nil {
			t.Errorf("ToolScript(%q) must fail: ops are not tools", op)
		}
	}
	if _, err := ToolScript("rm -rf /"); err == nil {
		t.Fatal("ToolScript must reject an unknown name")
	}
}

// The tool script is constant, so it diffs cleanly exactly as the ops do.
func TestToolScriptGolden(t *testing.T) {
	for _, tool := range Tools() {
		t.Run(tool, func(t *testing.T) {
			got, err := ToolScript(tool)
			if err != nil {
				t.Fatalf("ToolScript(%q): %v", tool, err)
			}
			path := filepath.Join("testdata", "golden", "tools", tool+".ps1")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run: go test ./internal/adscript -run TestToolScriptGolden -update)", err)
			}
			if got != string(want) {
				t.Errorf("script for %q changed; diff %s against the new output", tool, path)
			}
		})
	}
}

// A tool shares the preamble and epilogue, which is what makes its credential
// handling, error shape and framing identical to every op's rather than merely
// similar.
func TestToolScriptSharesTheEnvelope(t *testing.T) {
	s, err := ToolScript(ToolSchemaFetch)
	if err != nil {
		t.Fatalf("ToolScript: %v", err)
	}
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"Import-Module ActiveDirectory -ErrorAction Stop",
		"ConvertFrom-Json -AsHashtable",
		"$common['Credential']",
		"<<<TFAD:BEGIN>>>",
		"<<<TFAD:END>>>",
		"-Depth 6 -Compress",
		"(objectClass=attributeSchema)",
		"(objectClass=classSchema)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the schema fetch script is missing %q", want)
		}
	}
}
