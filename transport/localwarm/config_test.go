package localwarm

import (
	"testing"
)

func TestWithDefaults(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.PwshPath != "pwsh" {
		t.Errorf("PwshPath default = %q, want pwsh", c.PwshPath)
	}
	if c.Concurrency <= 0 || c.Timeout <= 0 || c.ReapAfter <= 0 || c.ReadTimeout <= 0 {
		t.Errorf("durations/concurrency must default positive: %+v", c)
	}
}

func TestValidateRejectsNegative(t *testing.T) {
	if err := (Config{Concurrency: -1}).Validate(); err == nil {
		t.Error("negative concurrency must be rejected")
	}
	if err := (Config{Timeout: -1}).Validate(); err == nil {
		t.Error("negative timeout must be rejected")
	}
	if err := (Config{ReapAfter: -1}).Validate(); err == nil {
		t.Error("negative reap-after must be rejected")
	}
	if err := (Config{ReadTimeout: -1}).Validate(); err == nil {
		t.Error("negative read-timeout must be rejected")
	}
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("a zero Config must validate (defaults fill it): %v", err)
	}
}
