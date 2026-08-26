package psrp

import (
	"testing"
	"time"
)

func TestWithDefaults(t *testing.T) {
	got := Config{Host: "dc.corp.local"}.WithDefaults()
	if got.Port != 5985 {
		t.Errorf("Port = %d, want 5985", got.Port)
	}
	if got.SPN != "HTTP/dc.corp.local" {
		t.Errorf("SPN = %q, want HTTP/dc.corp.local", got.SPN)
	}
	if got.ConfigurationName != "PowerShell.7" {
		t.Errorf("ConfigurationName = %q, want PowerShell.7", got.ConfigurationName)
	}
	if got.Concurrency != 4 {
		t.Errorf("Concurrency = %d, want 4", got.Concurrency)
	}
	if got.Timeout != 60*time.Second {
		t.Errorf("Timeout = %s, want 60s", got.Timeout)
	}
	if got.IdleTimeout != 2*time.Minute {
		t.Errorf("IdleTimeout = %s, want 2m", got.IdleTimeout)
	}
	if got.ReapAfter != 30*time.Second {
		t.Errorf("ReapAfter = %s, want 30s", got.ReapAfter)
	}
}

func TestWithDefaultsTLSPort(t *testing.T) {
	got := Config{Host: "dc.corp.local", UseTLS: true}.WithDefaults()
	if got.Port != 5986 {
		t.Errorf("Port = %d, want 5986", got.Port)
	}
}

// TestWithDefaultsIdleTimeoutExplicit: an explicit IdleTimeout survives
// WithDefaults unchanged. Zero means "use the default", not "no timeout" —
// there is deliberately no way to request an unbounded shell lease.
func TestWithDefaultsIdleTimeoutExplicit(t *testing.T) {
	got := Config{Host: "dc.corp.local", IdleTimeout: 5 * time.Minute}.WithDefaults()
	if got.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %s, want 5m", got.IdleTimeout)
	}
}

// TestWithDefaultsIdleTimeoutFloor: a sub-second positive value is raised to
// the 1-second floor rather than surviving to buildPSRPConfig, where
// int(d.Seconds()) would truncate anything under a second to 0 and emit
// "PT0S" — a lease the server could reap the shell under instantly, exactly
// the failure this field exists to prevent. The zero value is unaffected and
// still yields the 2-minute default (TestWithDefaults covers that case).
func TestWithDefaultsIdleTimeoutFloor(t *testing.T) {
	got := Config{Host: "dc.corp.local", IdleTimeout: 500 * time.Millisecond}.WithDefaults()
	if got.IdleTimeout != time.Second {
		t.Errorf("IdleTimeout = %s, want 1s (floored)", got.IdleTimeout)
	}

	pc := buildPSRPConfig(got)
	if pc.IdleTimeout != "PT1S" {
		t.Errorf("go-psrp IdleTimeout = %q, want PT1S (non-zero lease)", pc.IdleTimeout)
	}
}

// TestWithDefaultsReapAfterExplicit: an explicit ReapAfter survives
// WithDefaults unchanged, mirroring IdleTimeout's "zero means default"
// convention.
func TestWithDefaultsReapAfterExplicit(t *testing.T) {
	got := Config{Host: "dc.corp.local", ReapAfter: 5 * time.Minute}.WithDefaults()
	if got.ReapAfter != 5*time.Minute {
		t.Errorf("ReapAfter = %s, want 5m", got.ReapAfter)
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{Host: "dc"}).Validate(); err != nil {
		t.Errorf("valid config errored: %v", err)
	}
	if err := (Config{}).Validate(); err == nil {
		t.Error("missing host: want error, got nil")
	}
	if err := (Config{Host: "dc", InsecureSkipVerify: true}).Validate(); err == nil {
		t.Error("insecure without tls: want error, got nil")
	}
	if err := (Config{Host: "dc", Concurrency: -1}).Validate(); err == nil {
		t.Error("negative concurrency: want error, got nil")
	}
	if err := (Config{Host: "dc", IdleTimeout: -1}).Validate(); err == nil {
		t.Error("negative idle timeout: want error, got nil")
	}
	if err := (Config{Host: "dc", ReapAfter: -1}).Validate(); err == nil {
		t.Error("negative reap after: want error, got nil")
	}
}

func TestConfigLanguageMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		wantErr     bool
		constrained bool
	}{
		{"empty is full", "", false, false},
		{"full", "full", false, false},
		{"constrained", "constrained", false, true},
		{"invalid", "nolanguage", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Host: "h", LanguageMode: tc.mode}
			err := c.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && c.Constrained() != tc.constrained {
				t.Errorf("Constrained()=%v, want %v", c.Constrained(), tc.constrained)
			}
		})
	}
}
