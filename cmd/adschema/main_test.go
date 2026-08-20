package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func noEnv(string) string { return "" }

var fixedNow = time.Date(2026, 8, 20, 10, 41, 0, 0, time.UTC)

func TestParseArgsDefaults(t *testing.T) {
	cfg, err := parseArgs([]string{"--transport", "local"}, noEnv, fixedNow)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if want := []string{"organizationalUnit", "group", "user"}; strings.Join(cfg.classes, ",") != strings.Join(want, ",") {
		t.Errorf("classes = %v, want %v (the three the provider manages)", cfg.classes, want)
	}
	if cfg.all {
		t.Error("--classes all must not be the default")
	}
	if cfg.out != "schema/catalog.json" {
		t.Errorf("out = %q", cfg.out)
	}
	if !cfg.exportedAt.Equal(fixedNow) {
		t.Errorf("exportedAt = %v, want the clock passed in", cfg.exportedAt)
	}
	if cfg.spec.Kind != "local" || cfg.cred != nil {
		t.Errorf("spec = %+v, cred = %v", cfg.spec, cfg.cred)
	}
}

func TestParseArgsAllClasses(t *testing.T) {
	cfg, err := parseArgs([]string{"--transport", "local", "--classes", "all"}, noEnv, fixedNow)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.all || len(cfg.classes) != 0 {
		t.Errorf("all = %v, classes = %v", cfg.all, cfg.classes)
	}
}

func TestParseArgsTrimsAndRejectsAnEmptyClassList(t *testing.T) {
	cfg, err := parseArgs([]string{"--transport", "local", "--classes", " user , group "}, noEnv, fixedNow)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if strings.Join(cfg.classes, ",") != "user,group" {
		t.Errorf("classes = %v", cfg.classes)
	}
	if _, err := parseArgs([]string{"--transport", "local", "--classes", " , "}, noEnv, fixedNow); err == nil {
		t.Error("an empty class list must be an error, not an empty export")
	}
}

// A password never travels in argv, where the process list would show it.
func TestParseArgsReadsThePasswordFromTheNamedVariable(t *testing.T) {
	env := func(k string) string {
		if k == "LAB_PW" {
			return "s3cret"
		}
		return ""
	}
	cfg, err := parseArgs([]string{"--transport", "local", "--ad-username", `CORP\svc`, "--ad-password-env", "LAB_PW"}, env, fixedNow)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.cred == nil || cfg.cred.Username != `CORP\svc` || cfg.cred.Password != "s3cret" {
		t.Fatalf("cred = %+v", cfg.cred)
	}
	if _, err := parseArgs([]string{"--transport", "local", "--ad-username", "svc", "--ad-password-env", "UNSET_VAR"}, noEnv, fixedNow); err == nil {
		t.Error("an unset password variable must be an error rather than an empty password")
	}
	if _, err := parseArgs([]string{"--transport", "local", "--ad-username", "svc"}, noEnv, fixedNow); err == nil {
		t.Error("--ad-username without --ad-password-env must be an error")
	}
	if _, err := parseArgs([]string{"--transport", "local", "--ad-password-env", "LAB_PW"}, env, fixedNow); err == nil {
		t.Error("--ad-password-env without --ad-username must be an error")
	}
}

func TestParseArgsRejectsAMalformedTimestamp(t *testing.T) {
	if _, err := parseArgs([]string{"--transport", "local", "--exported-at", "yesterday"}, noEnv, fixedNow); err == nil {
		t.Error("--exported-at must be RFC 3339")
	}
	cfg, err := parseArgs([]string{"--transport", "local", "--exported-at", "2026-01-02T03:04:05Z"}, noEnv, fixedNow)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.exportedAt.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
		t.Errorf("exportedAt = %v", cfg.exportedAt)
	}
}

func TestRunRejectsAnythingButExport(t *testing.T) {
	if err := run([]string{}); err == nil || !strings.Contains(err.Error(), "export") {
		t.Errorf("no subcommand must name the one that exists: %v", err)
	}
	if err := run([]string{"import"}); err == nil || !strings.Contains(err.Error(), "export") {
		t.Errorf("an unknown subcommand must name the one that exists: %v", err)
	}
}

// The Kind is what a person acts on, and Target names the container AD refused
// — which Error() itself does not print.
func TestRenderAddsTheTargetAndTheRemedy(t *testing.T) {
	err := &adpwsh.Error{
		Kind:          adpwsh.KindDenied,
		Op:            "Schema.Fetch",
		ExceptionType: "System.UnauthorizedAccessException",
		ServerMessage: "Access is denied",
		Target:        "CN=Schema,CN=Configuration,DC=corp,DC=local",
	}
	got := render(err)
	for _, want := range []string{"CN=Schema", "read access to the schema naming context"} {
		if !strings.Contains(got, want) {
			t.Errorf("render() = %q, want it to contain %q", got, want)
		}
	}
	if got := render(errors.New("plain")); got != "plain" {
		t.Errorf("a plain error must pass through: %q", got)
	}
}

// writeFileAtomic is what guarantees a failed export never leaves a truncated
// catalog behind, because the next thing that reads the file is a commit.
// These three cases pin: the success path leaves exactly the one file behind
// (no leaked sibling temp file), a failure before any temp file could be
// created leaves nothing behind, and a failure after the temp file exists
// (rename losing to a name collision) still leaves nothing behind.

func TestWriteFileAtomicSuccessLeavesExactlyOneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	body := []byte(`{"hello":"world"}` + "\n")

	if err := writeFileAtomic(path, body); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if string(got) != string(body) {
		t.Errorf("file content = %q, want %q", got, body)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "catalog.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory contents = %v, want exactly [catalog.json] — a leaked temp file would show up here", names)
	}
}

func TestWriteFileAtomicFailureBeforeATempFileExistsLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	missingSubdir := filepath.Join(dir, "does-not-exist")
	path := filepath.Join(missingSubdir, "catalog.json")

	err := writeFileAtomic(path, []byte("irrelevant"))
	if err == nil {
		t.Fatal("writing into a nonexistent directory must fail")
	}
	if !strings.Contains(err.Error(), missingSubdir) {
		t.Errorf("error = %q, want it to name the directory %q", err, missingSubdir)
	}
	if _, statErr := os.Stat(missingSubdir); !os.IsNotExist(statErr) {
		t.Errorf("the directory must still not exist, got stat err = %v", statErr)
	}
}

// This is the branch where a temp file was already created, written and
// closed before the failure — a rename losing to an existing directory of
// the same name — so cleanup depends on the explicit os.Remove, not on the
// temp file never having existed in the first place.
func TestWriteFileAtomicRenameFailureLeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(%s): %v", path, err)
	}

	err := writeFileAtomic(path, []byte("irrelevant"))
	if err == nil {
		t.Fatal("renaming a file onto an existing directory must fail")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name %q", err, path)
	}

	entries, rdErr := os.ReadDir(dir)
	if rdErr != nil {
		t.Fatalf("ReadDir(%s): %v", dir, rdErr)
	}
	if len(entries) != 1 || entries[0].Name() != "target" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory contents = %v, want exactly [target] — a leaked temp file would show up here", names)
	}
}
