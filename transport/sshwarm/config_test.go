package sshwarm

import "testing"

func TestWithDefaults(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.Subsystem != "powershell" {
		t.Errorf("Subsystem default = %q, want powershell", c.Subsystem)
	}
	if c.ReapAfter <= 0 || c.ReadTimeout <= 0 {
		t.Errorf("durations must default positive: %+v", c)
	}
	// The embedded ssh config must be defaulted too (Port/Concurrency/Timeout).
	if c.SSH.Port != 22 || c.SSH.Concurrency <= 0 {
		t.Errorf("embedded ssh config must be defaulted: %+v", c.SSH)
	}
}

func TestValidateRequiresHost(t *testing.T) {
	if err := (Config{}).Validate(); err == nil {
		t.Error("must reject a config with no SSH host")
	}
}
