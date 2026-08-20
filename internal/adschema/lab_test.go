package adschema

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestExportAgainstTheLab is the only test in this module that needs a domain.
// It is gated rather than skipped silently: without ADSCHEMA_ACC it skips with
// a message naming what to set, and with ADSCHEMA_ACC set it fails loudly on a
// half-configured environment, because a half-configured run reporting green is
// worse than one reporting red.
func TestExportAgainstTheLab(t *testing.T) {
	if os.Getenv("ADSCHEMA_ACC") != "1" {
		t.Skip("set ADSCHEMA_ACC=1 and the ADSCHEMA_ACC_* variables to export against a domain")
	}
	spec, opts := labSpecFromEnv(t)

	tr, err := spec.Open()
	if err != nil {
		t.Fatalf("cannot open the %s transport: %v", spec.Kind, err)
	}
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout)
	defer cancel()

	raw, err := Fetch(ctx, tr, opts)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Logf("fetched %d attributes and %d classes from %s (objectVersion %d)",
		len(raw.Attributes), len(raw.Classes), raw.Source.Domain, raw.Source.ObjectVersion)

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // fixed: byte-identity is the assertion
	cat, err := Build(raw, []string{"organizationalUnit", "group", "user"}, at)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	checkInvariants(t, cat)

	for class, cl := range cat.Classes {
		t.Logf("%s: %d mandatory + %d optional = %d effective",
			class, len(cl.Mandatory), len(cl.Optional), len(cl.Mandatory)+len(cl.Optional))
	}

	// Exporting twice must produce identical bytes. Given the same schema and
	// the same timestamp, the only way this fails is a non-deterministic
	// closure or emit — the two things a data artefact cannot afford.
	first, err := Emit(cat)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	rawAgain, err := Fetch(ctx, tr, opts)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	catAgain, err := Build(rawAgain, []string{"organizationalUnit", "group", "user"}, at)
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	second, err := Emit(catAgain)
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two exports of the same schema differ (%d vs %d bytes)", len(first), len(second))
	}
}

// labSpecFromEnv builds the transport from the environment, so the CLI's flags
// and this test open a transport exactly one way. A variable that is required
// once ADSCHEMA_ACC is set is a Fatal, not a default.
func labSpecFromEnv(t *testing.T) (TransportSpec, FetchOptions) {
	t.Helper()
	spec := TransportSpec{
		Kind:     os.Getenv("ADSCHEMA_ACC_TRANSPORT"),
		PwshPath: os.Getenv("ADSCHEMA_ACC_PWSH_PATH"),
		Timeout:  5 * time.Minute,
	}
	switch spec.Kind {
	case "local":
	case "ssh":
		spec.SSHHost = os.Getenv("ADSCHEMA_ACC_SSH_HOST")
		spec.SSHUser = os.Getenv("ADSCHEMA_ACC_SSH_USER")
		spec.SSHPrivateKeyPath = os.Getenv("ADSCHEMA_ACC_SSH_KEY_PATH")
		spec.SSHKnownHostsFile = os.Getenv("ADSCHEMA_ACC_SSH_KNOWN_HOSTS")
		spec.SSHInsecureIgnoreHostKey = os.Getenv("ADSCHEMA_ACC_SSH_INSECURE") == "1"
		spec.SSHPort = 22
		if p := os.Getenv("ADSCHEMA_ACC_SSH_PORT"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				t.Fatalf("ADSCHEMA_ACC_SSH_PORT=%q is not a number", p)
			}
			spec.SSHPort = n
		}
		if spec.SSHHost == "" || spec.SSHUser == "" {
			t.Fatal("ADSCHEMA_ACC_SSH_HOST and ADSCHEMA_ACC_SSH_USER are required for the ssh transport")
		}
	default:
		t.Fatalf("ADSCHEMA_ACC_TRANSPORT=%q; set it to local or ssh", spec.Kind)
	}

	opts := FetchOptions{Server: os.Getenv("ADSCHEMA_ACC_SERVER")}
	user, pass := os.Getenv("ADSCHEMA_ACC_AD_USERNAME"), os.Getenv("ADSCHEMA_ACC_AD_PASSWORD")
	switch {
	case user != "" && pass != "":
		opts.Credential = &Credential{Username: user, Password: pass}
	case user != "" || pass != "":
		t.Fatal("set both ADSCHEMA_ACC_AD_USERNAME and ADSCHEMA_ACC_AD_PASSWORD, or neither")
	}
	return spec, opts
}
