package adpwsh_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func groupData(name, sam, container, scope string) map[string]any {
	return map[string]any{
		"objectGUID":        "aa11bb22-0000-0000-0000-000000000002",
		"distinguishedName": "CN=" + name + "," + container,
		"name":              name,
		"samAccountName":    sam,
		"scope":             scope,
		"category":          "security",
		"description":       "",
		"managedBy":         "",
		"sid":               "S-1-5-21-1-2-3-1201",
	}
}

func TestGroupCreate(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "group_create":
			create, _ = c.Payload["create"].(map[string]any)
			return fake.OK(groupData("Developers", "developers", "OU=Staff,DC=corp,DC=local", "global"))
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	g, err := client.Group.Create(context.Background(), adpwsh.GroupSpec{
		Name:           "Developers",
		SamAccountName: "developers",
		Container:      "OU=Staff,DC=corp,DC=local",
		Scope:          adpwsh.GroupScopeGlobal,
		Category:       adpwsh.GroupCategorySecurity,
		ManagedBy:      adpwsh.String("CN=Alice,OU=Staff,DC=corp,DC=local"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The cmdlet's accepted values are PascalCase; the library's surface is
	// lowercase. The mapping happens once, here.
	if create["GroupScope"] != "Global" || create["GroupCategory"] != "Security" {
		t.Errorf("create splat = %v", create)
	}
	if create["Name"] != "Developers" || create["SamAccountName"] != "developers" ||
		create["Path"] != "OU=Staff,DC=corp,DC=local" ||
		create["ManagedBy"] != "CN=Alice,OU=Staff,DC=corp,DC=local" {
		t.Errorf("create splat = %v", create)
	}
	if g.Scope != adpwsh.GroupScopeGlobal || g.SID == "" || g.Container != "OU=Staff,DC=corp,DC=local" {
		t.Errorf("group = %+v", g)
	}
}

func TestGroupCreateValidation(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	client := mustClient(t, adpwsh.Config{Transport: tr})
	base := adpwsh.GroupSpec{
		Name: "Developers", SamAccountName: "developers",
		Container: "OU=Staff,DC=corp,DC=local", Scope: adpwsh.GroupScopeGlobal,
	}
	tests := []struct {
		name string
		mut  func(*adpwsh.GroupSpec)
		want string
	}{
		{"no sam", func(s *adpwsh.GroupSpec) { s.SamAccountName = "" }, "SamAccountName"},
		{"no scope", func(s *adpwsh.GroupSpec) { s.Scope = "" }, "Scope"},
		{"bad scope", func(s *adpwsh.GroupSpec) { s.Scope = "worldwide" }, "Scope"},
		{"bad category", func(s *adpwsh.GroupSpec) { s.Category = "mailing-list" }, "Category"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := base
			tt.mut(&spec)
			_, err := client.Group.Create(context.Background(), spec)
			if err == nil {
				t.Fatal("expected a validation error before any round trip")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should name %q", err, tt.want)
			}
		})
	}
}

// sam_account_name changes through Set-ADGroup, not through a replace.
func TestGroupUpdateChangesSamScopeAndCategory(t *testing.T) {
	var payload map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "group_read":
			return fake.OK(groupData("Developers", "developers", "OU=Staff,DC=corp,DC=local", "global"))
		case "group_update":
			payload = c.Payload
			return fake.OK(groupData("Developers", "devs", "OU=Staff,DC=corp,DC=local", "universal"))
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.Group.Update(context.Background(), adpwsh.ByGUID("aa11"), adpwsh.GroupSpec{
		Name: "Developers", SamAccountName: "devs", Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeUniversal, Category: adpwsh.GroupCategorySecurity,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	set, _ := payload["set"].(map[string]any)
	if set["SamAccountName"] != "devs" || set["GroupScope"] != "Universal" {
		t.Errorf("set = %v", set)
	}
	if _, present := payload["rename"]; present {
		t.Errorf("the CN did not change; no rename should be issued: %v", payload)
	}
}

// AD refuses certain scope conversions. Its own error is surfaced; the library
// never chooses a destructive replace on its own initiative.
func TestGroupUpdateSurfacesARefusedScopeConversion(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "group_read":
			return fake.OK(groupData("Developers", "developers", "OU=Staff,DC=corp,DC=local", "global"))
		default:
			return fake.Fail("Microsoft.ActiveDirectory.Management.ADInvalidOperationException",
				"The requested operation did not satisfy one or more constraints", 0x2035)
		}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	_, err := client.Group.Update(context.Background(), adpwsh.ByGUID("aa11"), adpwsh.GroupSpec{
		Name: "Developers", SamAccountName: "developers", Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeDomainLocal,
	})
	if !errors.Is(err, adpwsh.ErrConstraint) {
		t.Fatalf("want KindConstraint, got %v", err)
	}
}

func TestGroupDeleteVerifiesAbsence(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "group_read":
			return fake.OK(groupData("Developers", "developers", "OU=Staff,DC=corp,DC=local", "global"))
		case "group_delete":
			return fake.OK(map[string]any{"deleted": true, "verify": map[string]any{"found": true}})
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	err := client.Group.Delete(context.Background(), adpwsh.ByGUID("aa11"))
	if err == nil {
		t.Fatal("a delete that left the object present must be an error")
	}
}
