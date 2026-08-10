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
