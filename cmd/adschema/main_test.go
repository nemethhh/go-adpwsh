package main

import (
	"errors"
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
