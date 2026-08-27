package sshwarm

import (
	"errors"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

func TestNewRejectsBadConfig(t *testing.T) {
	_, err := New(Config{}) // no SSH host
	if err == nil {
		t.Fatal("New must reject an invalid config")
	}
	var ae *adpwsh.Error
	if !errors.As(err, &ae) {
		t.Fatalf("want *adpwsh.Error, got %T", err)
	}
}

func TestNewDoesNotDialAtConstruction(t *testing.T) {
	// A well-formed config to an unreachable host must still construct: the warm
	// pool connects lazily on first Run, so New must NOT dial (unlike
	// transport/ssh.New, which dials eagerly). InsecureIgnoreHostKey is set only
	// to satisfy Validate's host-key-source requirement; nothing dials here.
	tr, err := New(Config{SSH: adssh.Config{
		Host: "203.0.113.1", User: "x", Password: "y", InsecureIgnoreHostKey: true,
	}})
	if err != nil {
		t.Fatalf("New should not dial (lazy connect); got %v", err)
	}
	_ = tr.Close()
}
