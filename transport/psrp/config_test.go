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
}

func TestWithDefaultsTLSPort(t *testing.T) {
	got := Config{Host: "dc.corp.local", UseTLS: true}.WithDefaults()
	if got.Port != 5986 {
		t.Errorf("Port = %d, want 5986", got.Port)
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
}
