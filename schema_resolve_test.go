package adpwsh_test

import (
	"context"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func TestSchemaResolveWellKnownSkipsRoundTrip(t *testing.T) {
	var called bool
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "schema_resolve":
			called = true
			return fake.OK(map[string]any{"resolved": map[string]any{}})
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	got, err := client.Schema.Resolve(context.Background(), []adpwsh.SchemaRef{
		{Kind: adpwsh.RefExtendedRight, Name: "Reset Password"},
		{Kind: adpwsh.RefClass, Name: "user"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if called {
		t.Error("schema_resolve was called for names in the well-known table")
	}
	if got[adpwsh.SchemaRef{Kind: adpwsh.RefExtendedRight, Name: "Reset Password"}] != "00299570-246d-11d0-a768-00aa006e0529" {
		t.Errorf("Reset Password = %q", got[adpwsh.SchemaRef{Kind: adpwsh.RefExtendedRight, Name: "Reset Password"}])
	}
}

func TestSchemaResolveFallsBackToDirectory(t *testing.T) {
	var gotFilter string
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "schema_resolve":
			refs, _ := c.Payload["refs"].([]any)
			first, _ := refs[0].(map[string]any)
			gotFilter, _ = first["filter"].(string)
			return fake.OK(map[string]any{"resolved": map[string]any{
				"custom-attr": "11111111-2222-3333-4444-555555555555",
			}})
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	got, err := client.Schema.Resolve(context.Background(),
		[]adpwsh.SchemaRef{{Kind: adpwsh.RefAttribute, Name: "custom-attr"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got[adpwsh.SchemaRef{Kind: adpwsh.RefAttribute, Name: "custom-attr"}] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("custom-attr = %q", got[adpwsh.SchemaRef{Kind: adpwsh.RefAttribute, Name: "custom-attr"}])
	}
	if gotFilter != "(&(objectClass=attributeSchema)(lDAPDisplayName=custom-attr))" {
		t.Errorf("filter = %q", gotFilter)
	}
}
