package psrp

import (
	"testing"
	"time"
)

// TestBuildPSRPConfigIdleTimeoutDefault: newClient's go-psrp config must carry
// a short, non-empty IdleTimeout. Left unset, go-psrp itself requests a
// 30-minute shell lease (PT30M) — the root cause of the WinRM-shell leak this
// change closes — so this must never come back empty.
func TestBuildPSRPConfigIdleTimeoutDefault(t *testing.T) {
	cfg := Config{Host: "dc"}.WithDefaults()
	pc := buildPSRPConfig(cfg)
	if pc.IdleTimeout == "" {
		t.Fatal("IdleTimeout is empty; go-psrp will fall back to its own PT30M default")
	}
	if pc.IdleTimeout != "PT120S" {
		t.Errorf("IdleTimeout = %q, want PT120S (2 minutes)", pc.IdleTimeout)
	}
}

// TestBuildPSRPConfigIdleTimeoutExplicit: an explicit Config.IdleTimeout is
// translated verbatim into the ISO8601 form go-psrp expects.
func TestBuildPSRPConfigIdleTimeoutExplicit(t *testing.T) {
	cfg := Config{Host: "dc", IdleTimeout: 5 * time.Minute}.WithDefaults()
	pc := buildPSRPConfig(cfg)
	if pc.IdleTimeout != "PT300S" {
		t.Errorf("IdleTimeout = %q, want PT300S (5 minutes)", pc.IdleTimeout)
	}
}

// TestBuildPSRPConfigLeavesGoPSRPRetryMachineryOff: warm's own pool does
// exactly one bounded, narrowly-scoped retry (see isDeadShellFailure). Nothing
// enforces that go-psrp's own retry machinery stays out of the way — if
// Config.Retry or Config.Reconnect were ever enabled (by us, or by a future
// go-psrp default change), its retries would compound with ours and
// reintroduce the double-execution risk this transport is built to avoid.
// buildPSRPConfig never touches either field, so psrp.DefaultConfig()'s own
// defaults (Retry: nil, Reconnect.Enabled: false) must survive untouched.
func TestBuildPSRPConfigLeavesGoPSRPRetryMachineryOff(t *testing.T) {
	pc := buildPSRPConfig(Config{Host: "dc"}.WithDefaults())
	if pc.Retry != nil {
		t.Errorf("Retry = %+v, want nil (go-psrp's own command retry must stay disabled)", pc.Retry)
	}
	if pc.Reconnect.Enabled {
		t.Error("Reconnect.Enabled = true, want false (go-psrp's own reconnect policy must stay disabled)")
	}
}

// TestNewReportsConstrained: New builds a real warm pool (which populates via
// newClient -> psrp.New, doing no network I/O and connecting lazily, so it does
// not dial), and the resulting Transport reports the endpoint's language mode
// through the Constrained() signal core.exec probes for. Close drains the pool
// and stops the reaper.
//
// Username/Password are supplied only because go-psrp's own psrp.New validates
// credentials up front (it still opens no connection); the value under test is
// purely that New wires Config.Constrained() through to the Transport.
func TestNewReportsConstrained(t *testing.T) {
	tr, err := New(Config{Host: "h", Username: "u", Password: "p", LanguageMode: "constrained"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()
	if !tr.Constrained() {
		t.Fatal("constrained endpoint must report Constrained()==true")
	}
}
