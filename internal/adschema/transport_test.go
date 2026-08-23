package adschema

import (
	"strings"
	"testing"
	"time"
)

func TestOpenRequiresAKnownTransport(t *testing.T) {
	if _, err := (TransportSpec{}).Open(); err == nil || !strings.Contains(err.Error(), "--transport") {
		t.Errorf("an unset transport must say which flag is missing: %v", err)
	}
	if _, err := (TransportSpec{Kind: "winrm"}).Open(); err == nil || !strings.Contains(err.Error(), "winrm") {
		t.Errorf("an unknown transport must name it: %v", err)
	}
}

// The library's own validation is what reports a missing host key source or two
// auth methods. The exporter must not restate those rules, so the test asserts
// the library's message reaches the operator.
func TestOpenDefersToTheLibrarysValidation(t *testing.T) {
	_, err := TransportSpec{Kind: "ssh", Timeout: time.Minute, SSHHost: "dc01", SSHUser: "svc"}.Open()
	if err == nil {
		t.Fatal("ssh with no auth source must fail")
	}
	if !strings.Contains(err.Error(), "exactly one of") {
		t.Errorf("the library's own message must reach the operator: %v", err)
	}
}

func TestOpenPSRPRequiresHost(t *testing.T) {
	// psrp is now a known kind; opening it with no host is a config error,
	// not an "unknown transport" error.
	_, err := (TransportSpec{Kind: "psrp"}).Open()
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("want a host-required error, got %v", err)
	}
}
