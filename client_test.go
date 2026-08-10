package adpwsh_test

import (
	"context"
	"errors"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func rootDSE() map[string]any {
	return map[string]any{
		"dnsHostName":          "dc01.corp.local",
		"defaultNamingContext": "DC=corp,DC=local",
		"schemaNamingContext":  "CN=Schema,CN=Configuration,DC=corp,DC=local",
	}
}

func TestNewRequiresATransport(t *testing.T) {
	_, err := adpwsh.New(context.Background(), adpwsh.Config{})
	if err == nil {
		t.Fatal("New must reject a Config with no Transport")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
}

// Without pinning, a create lands on DC-A and the read-back hits DC-B, which
// returns "not found". Every call carries the same -Server for the client's
// lifetime.
func TestNewDiscoversAndPinsTheDC(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op != "rootdse" {
			t.Fatalf("unexpected op %q during New", c.Op)
		}
		if _, ok := c.Payload["server"]; ok {
			t.Error("an unpinned client must not send a server on the discovery call")
		}
		return fake.OK(rootDSE())
	})
	c, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Server() != "dc01.corp.local" {
		t.Errorf("Server() = %q, want the discovered DC", c.Server())
	}
	if c.DefaultNamingContext() != "DC=corp,DC=local" {
		t.Errorf("DefaultNamingContext() = %q", c.DefaultNamingContext())
	}
}

func TestNewKeepsAnExplicitServer(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Payload["server"] != "dc09.corp.local" {
			t.Errorf("server = %v, want the pinned DC", c.Payload["server"])
		}
		return fake.OK(rootDSE())
	})
	c, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr, Server: "dc09.corp.local"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Server() != "dc09.corp.local" {
		t.Errorf("Server() = %q; an explicit server must win over the rootDSE answer", c.Server())
	}
}

func TestNewSurfacesAnUnreachableJumpBox(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Raw("", "Import-Module: The specified module 'ActiveDirectory' was not loaded", 1)
	})
	_, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr})
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Fatalf("want KindTransport, got %v", err)
	}
}

func TestClientCloseClosesTheTransport(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	c, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !tr.Closed() {
		t.Error("Close must release the transport")
	}
}
