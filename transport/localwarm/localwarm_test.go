package localwarm

import (
	"errors"
	"os/exec"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func TestNewFailsWithoutPwsh(t *testing.T) {
	_, err := New(Config{PwshPath: "definitely-not-a-real-pwsh-binary-xyz"})
	if err == nil {
		t.Fatal("New must fail when pwsh 7 is not found")
	}
	var ae *adpwsh.Error
	if !errors.As(err, &ae) {
		t.Fatalf("want *adpwsh.Error, got %T", err)
	}
}

func TestNewReturnsTransport(t *testing.T) {
	// With a resolvable pwsh path, New wires the pool WITHOUT dialing (each conn
	// connects lazily on first Run), so this must not spawn a process. Skip
	// where pwsh is absent (CI without pwsh); wiring is proven end-to-end by the
	// localwarmlive integration test.
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("pwsh not on PATH; wiring covered by the localwarmlive integration test")
	}
	tr, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
