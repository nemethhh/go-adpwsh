package adpwsh_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func ouAt(name, container string) map[string]any {
	return map[string]any{
		"objectGUID":        "9f2c8f1e-0000-0000-0000-000000000001",
		"distinguishedName": "OU=" + name + "," + container,
		"name":              name,
		"description":       "",
		"protected":         true,
	}
}

func TestOUCreateSendsTheRightPayloadAndReadsBack(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			create, _ = c.Payload["create"].(map[string]any)
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	ou, err := client.OU.Create(context.Background(), adpwsh.OUSpec{
		Name:        "Staff",
		Container:   "DC=corp,DC=local",
		Description: adpwsh.String("The staff OU"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if create["Name"] != "Staff" || create["Path"] != "DC=corp,DC=local" || create["Description"] != "The staff OU" {
		t.Errorf("create splat = %v", create)
	}
	// Correctness rule 1: what comes back is the Get path's result, so an
	// inconsistent result after apply is impossible by construction.
	if ou.GUID == "" || ou.DN != "OU=Staff,DC=corp,DC=local" {
		t.Errorf("ou = %+v", ou)
	}
	// container is derived from the DN, never echoed by the script.
	if ou.Container != "DC=corp,DC=local" {
		t.Errorf("Container = %q", ou.Container)
	}
}

func TestOUCreateValidatesTheSpec(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	client := mustClient(t, adpwsh.Config{Transport: tr})
	tests := []struct {
		name string
		spec adpwsh.OUSpec
	}{
		{"no name", adpwsh.OUSpec{Container: "DC=corp,DC=local"}},
		{"no container", adpwsh.OUSpec{Name: "Staff"}},
		{"container is not a DN", adpwsh.OUSpec{Name: "Staff", Container: "not a dn"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.OU.Create(context.Background(), tt.spec); err == nil {
				t.Fatal("expected a validation error before any round trip")
			}
		})
	}
}

// An already-exists during create that traces to a deleted object is a named
// condition, not an opaque failure (correctness rule 8).
func TestOUCreateDetectsATombstone(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			return fake.Fail("Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException", "exists", 0x1392)
		case "deleted_probe":
			return fake.OK(map[string]any{"matches": []any{map[string]any{
				"objectGUID":        "dead0000-0000-0000-0000-000000000001",
				"distinguishedName": `OU=Staff\0ADEL:dead…,CN=Deleted Objects,DC=corp,DC=local`,
				"lastKnownParent":   "DC=corp,DC=local",
			}}})
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	_, err := client.OU.Create(context.Background(), adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"})
	if !errors.Is(err, adpwsh.ErrAlreadyExists) {
		t.Fatalf("want KindAlreadyExists, got %v", err)
	}
	var e *adpwsh.Error
	if !errors.As(err, &e) || !e.Tombstoned {
		t.Errorf("Tombstoned not set: %+v", e)
	}
}

// Rename and move are folded into one write, in the order that keeps the DN
// valid, and never a delete-and-recreate.
func TestOUUpdateFoldsRenameAndMove(t *testing.T) {
	var payload map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_read":
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		case "ou_update":
			payload = c.Payload
			return fake.OK(ouAt("People", "OU=HQ,DC=corp,DC=local"))
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	ou, err := client.OU.Update(context.Background(), adpwsh.ByGUID("9f2c"), adpwsh.OUSpec{
		Name:        "People",
		Container:   "OU=HQ,DC=corp,DC=local",
		Description: adpwsh.String("Everyone"),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	set, _ := payload["set"].(map[string]any)
	if set["Description"] != "Everyone" {
		t.Errorf("set = %v", set)
	}
	rename, _ := payload["rename"].(map[string]any)
	if rename["NewName"] != "People" {
		t.Errorf("rename = %v", rename)
	}
	move, _ := payload["move"].(map[string]any)
	if move["TargetPath"] != "OU=HQ,DC=corp,DC=local" {
		t.Errorf("move = %v", move)
	}
	if ou.Name != "People" {
		t.Errorf("read-back = %+v", ou)
	}
}

// AD echoes DNs in its own case; comparing them as strings would move an OU
// onto itself on every apply.
func TestOUUpdateIgnoresDNCaseAndIsANoopWhenNothingChanged(t *testing.T) {
	var updates int
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_read":
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		case "ou_update":
			updates++
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.OU.Update(context.Background(), adpwsh.ByGUID("9f2c"), adpwsh.OUSpec{
		Name: "Staff", Container: "dc=CORP,dc=local",
	}); err != nil {
		t.Fatal(err)
	}
	if updates != 0 {
		t.Errorf("issued %d writes for an unchanged object, want 0", updates)
	}
}

// Both null and an empty string clear, and a clear is -Clear, never
// -Replace with "".
func TestOUUpdateClearsWithClearNotReplace(t *testing.T) {
	var set map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_read":
			d := ouAt("Staff", "DC=corp,DC=local")
			d["description"] = "old"
			return fake.OK(d)
		case "ou_update":
			set, _ = c.Payload["set"].(map[string]any)
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.OU.Update(context.Background(), adpwsh.ByGUID("9f2c"), adpwsh.OUSpec{
		Name: "Staff", Container: "DC=corp,DC=local", Description: adpwsh.String(""),
	}); err != nil {
		t.Fatal(err)
	}
	clear, _ := set["Clear"].([]any)
	if len(clear) != 1 || clear[0] != "description" {
		t.Errorf("Clear = %v, want [description]", set["Clear"])
	}
	if _, present := set["Replace"]; present {
		t.Errorf("a clear must not emit Replace: %v", set)
	}
}

// Correctness rule 5: a Remove-AD* that returns cleanly while the deletion was
// refused is an error, not a success.
func TestOUDeleteVerifiesAbsence(t *testing.T) {
	tests := []struct {
		name    string
		verify  map[string]any
		wantErr bool
	}{
		{"gone", map[string]any{"found": false,
			"type": "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException", "errorCode": 8333}, false},
		{"still there", map[string]any{"found": true}, true},
		{"lookup failed for another reason", map[string]any{"found": false,
			"type": "Microsoft.ActiveDirectory.Management.ADServerDownException"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := fake.New(func(c fake.Call) fake.Response {
				switch c.Op {
				case "rootdse":
					return fake.OK(rootDSE())
				case "ou_read":
					return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
				case "ou_delete":
					if c.Payload["unprotect"] != true {
						t.Error("Unprotect: true must reach the script")
					}
					return fake.OK(map[string]any{"deleted": true, "childCount": 0, "verify": tt.verify})
				}
				return fake.Response{}
			})
			client := mustClient(t, adpwsh.Config{Transport: tr})
			err := client.OU.Delete(context.Background(), adpwsh.ByGUID("9f2c"), adpwsh.DeleteOptions{Unprotect: true})
			if tt.wantErr != (err != nil) {
				t.Fatalf("Delete error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// A non-empty OU is never deleted recursively; the error names the child count.
func TestOUDeleteRefusesANonEmptyOU(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_read":
			return fake.OK(ouAt("Staff", "DC=corp,DC=local"))
		case "ou_delete":
			return fake.OK(map[string]any{"deleted": false, "childCount": 7})
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	err := client.OU.Delete(context.Background(), adpwsh.ByGUID("9f2c"), adpwsh.DeleteOptions{Unprotect: true})
	if !errors.Is(err, adpwsh.ErrConstraint) {
		t.Fatalf("want KindConstraint, got %v", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("the error must name the child count: %v", err)
	}
}
