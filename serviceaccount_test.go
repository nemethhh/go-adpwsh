package adpwsh_test

import (
	"context"
	"errors"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

// TestServiceAccountCreateGet drives a full create → read round trip against
// fake.Directory, the same in-memory AD the OU/User/Group lifecycle tests in
// search_client_test.go and transport/fake/directory_test.go use. mustClient
// (core_test.go) is the same helper user_test.go's suite builds its client
// with; there is no separate "newFakeClient" — combining it with
// fake.NewDirectory() is enough, so no new helper is introduced.
func TestServiceAccountCreateGet(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})

	g, err := client.ServiceAccount.Create(context.Background(), adpwsh.GMSASpec{
		Name: "svc-web", SamAccountName: "svc-web",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("svc-web.corp.local"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// AD itself appends the trailing "$" to a gMSA's sAMAccountName.
	if g.SamAccountName != "svc-web$" {
		t.Fatalf("sam = %q, want svc-web$", g.SamAccountName)
	}
	if g.DNSHostName != "svc-web.corp.local" || g.Container != "OU=x,DC=corp,DC=local" {
		t.Fatalf("created gMSA = %+v", g)
	}

	got, err := client.ServiceAccount.Get(context.Background(), adpwsh.ByGUID(g.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GUID != g.GUID || got.SamAccountName != "svc-web$" || got.DNSHostName != "svc-web.corp.local" {
		t.Fatalf("Get round trip = %+v, want match of %+v", got, g)
	}
}

// TestServiceAccountCreateSendsThePinnedSplatKeys locks the create payload to
// the exact keys the fake (Task 3) and the real New-ADServiceAccount cmdlet
// both expect: PrincipalsAllowed through identityArgs, SPNs and
// KerberosEncryptionType as plain lists, and ManagedPasswordIntervalInDays
// only when the spec sets it.
func TestServiceAccountCreateSendsThePinnedSplatKeys(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "gmsa_create":
			create, _ = c.Payload["create"].(map[string]any)
			return fake.OK(gmsaData())
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	spns := []string{"HTTP/svc-web.corp.local"}
	kerb := []string{"AES256"}
	_, err := client.ServiceAccount.Create(context.Background(), adpwsh.GMSASpec{
		Name: "svc-web", SamAccountName: "svc-web",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("svc-web.corp.local"),
		Description: adpwsh.String("web tier"), DisplayName: adpwsh.String("Web Service"),
		Enabled: adpwsh.Bool(true), TrustedForDelegation: adpwsh.Bool(false),
		PrincipalsAllowed:             []adpwsh.Identity{adpwsh.ByGUID("11111111-1111-1111-1111-111111111111")},
		ServicePrincipalNames:         &spns,
		KerberosEncryptionType:        &kerb,
		ManagedPasswordIntervalInDays: adpwsh.Int(45),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if create["Name"] != "svc-web" || create["SamAccountName"] != "svc-web" ||
		create["Path"] != "OU=x,DC=corp,DC=local" || create["DNSHostName"] != "svc-web.corp.local" {
		t.Fatalf("create splat base = %v", create)
	}
	if create["Description"] != "web tier" || create["DisplayName"] != "Web Service" {
		t.Errorf("create splat optional strings = %v", create)
	}
	if create["Enabled"] != true || create["TrustedForDelegation"] != false {
		t.Errorf("create splat booleans = %v", create)
	}
	// The payload rode through a real JSON marshal (core.exec) and unmarshal
	// (fake.Transport.Run), so a []string on the way in decodes as []any on
	// the way out here — the same reason transport/fake's own toStringSlice
	// helper exists.
	principals := toStrs(create["PrincipalsAllowedToRetrieveManagedPassword"])
	if len(principals) != 1 || principals[0] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("PrincipalsAllowedToRetrieveManagedPassword = %v, want the one GUID via identityArgs", create["PrincipalsAllowedToRetrieveManagedPassword"])
	}
	spnGot := toStrs(create["ServicePrincipalNames"])
	if len(spnGot) != 1 || spnGot[0] != "HTTP/svc-web.corp.local" {
		t.Errorf("ServicePrincipalNames = %v, want a plain list", create["ServicePrincipalNames"])
	}
	kerbGot := toStrs(create["KerberosEncryptionType"])
	if len(kerbGot) != 1 || kerbGot[0] != "AES256" {
		t.Errorf("KerberosEncryptionType = %v, want a plain list", create["KerberosEncryptionType"])
	}
	if create["ManagedPasswordIntervalInDays"] != float64(45) {
		t.Errorf("ManagedPasswordIntervalInDays = %v (%T), want 45", create["ManagedPasswordIntervalInDays"], create["ManagedPasswordIntervalInDays"])
	}
}

// toStrs converts a JSON-decoded []any of strings back to []string, since a
// Go []string sent through a real JSON marshal/unmarshal round trip (as the
// fake.New-backed tests do) comes back as []any.
func toStrs(v any) []string {
	a, _ := v.([]any)
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// TestServiceAccountCreateOmitsManagedPasswordIntervalWhenUnset pins the
// tri-state rule: the spec's pointer is nil, so the key must not appear at
// all (not even as a zero value), matching "only add a key when the spec
// provides it."
func TestServiceAccountCreateOmitsManagedPasswordIntervalWhenUnset(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		create, _ = c.Payload["create"].(map[string]any)
		return fake.OK(gmsaData())
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.ServiceAccount.Create(context.Background(), adpwsh.GMSASpec{
		Name: "svc-web", SamAccountName: "svc-web",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("svc-web.corp.local"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, present := create["ManagedPasswordIntervalInDays"]; present {
		t.Errorf("ManagedPasswordIntervalInDays must be absent when the spec's pointer is nil: %v", create)
	}
	if _, present := create["PrincipalsAllowedToRetrieveManagedPassword"]; present {
		t.Errorf("PrincipalsAllowedToRetrieveManagedPassword must be absent when PrincipalsAllowed is nil: %v", create)
	}
}

// TestServiceAccountGetProjectsTheExtendedProperties pins the CARRY-FORWARD
// finding from the Task 2 review: Get-ADServiceAccount does not return the
// gMSA-specific properties by default, so gmsaProject must name every one of
// them.
func TestServiceAccountGetProjectsTheExtendedProperties(t *testing.T) {
	var project []string
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "gmsa_read":
			if p, ok := c.Payload["project"].([]any); ok {
				for _, v := range p {
					project = append(project, v.(string))
				}
			}
			return fake.OK(gmsaData())
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.ServiceAccount.Get(context.Background(), adpwsh.ByGUID("cc33")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DNSHostName", "Description", "DisplayName", "Enabled", "TrustedForDelegation",
		"PrincipalsAllowedToRetrieveManagedPassword", "ServicePrincipalNames",
		"KerberosEncryptionType", "ManagedPasswordIntervalInDays", "AccountExpirationDate",
	}
	got := map[string]bool{}
	for _, p := range project {
		got[p] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("gmsaProject is missing %q: %v", w, project)
		}
	}
}

// TestServiceAccountSearchOverFake exercises Search's class-scoped read
// against fake.Directory, mirroring TestUserSearchScopeAndFilterOverFake in
// search_client_test.go.
func TestServiceAccountSearchOverFake(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})
	ctx := context.Background()

	a, err := client.ServiceAccount.Create(ctx, adpwsh.GMSASpec{
		Name: "svc-a", SamAccountName: "svc-a",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("svc-a.corp.local"),
	})
	if err != nil {
		t.Fatalf("create svc-a: %v", err)
	}
	if _, err := client.ServiceAccount.Create(ctx, adpwsh.GMSASpec{
		Name: "svc-b", SamAccountName: "svc-b",
		Container: "OU=y,DC=corp,DC=local", DNSHostName: adpwsh.String("svc-b.corp.local"),
	}); err != nil {
		t.Fatalf("create svc-b: %v", err)
	}

	got, err := client.ServiceAccount.Search(ctx, adpwsh.Query{
		SearchBase: "OU=x,DC=corp,DC=local", Scope: adpwsh.SearchScopeOneLevel,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].GUID != a.GUID {
		t.Fatalf("scoped search = %+v, want just svc-a", got)
	}

	all, err := client.ServiceAccount.Search(ctx, adpwsh.Query{})
	if err != nil {
		t.Fatalf("Search (subtree): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("subtree search = %d results, want 2", len(all))
	}
}

// TestServiceAccountCreateRejectsMissingDNSHostName exercises the real call
// path (Client.ServiceAccount.Create), not spec.validate directly. DNSHostName
// is documented as required on create; a spec that omits it must be rejected
// with KindConstraint before any round trip, not silently accepted.
func TestServiceAccountCreateRejectsMissingDNSHostName(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		t.Fatalf("validation must fail before any round trip; got op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	_, err := client.ServiceAccount.Create(context.Background(), adpwsh.GMSASpec{
		Name: "svc-web", SamAccountName: "svc-web", Container: "OU=x,DC=corp,DC=local",
		// DNSHostName deliberately omitted.
	})
	if err == nil {
		t.Fatal("Create with no DNSHostName must fail; it did not")
	}
	if !errors.Is(err, adpwsh.ErrConstraint) {
		t.Fatalf("want KindConstraint, got %v", err)
	}
}

func gmsaData() map[string]any {
	return map[string]any{
		"objectGUID":                    "dd44ee55-0000-0000-0000-000000000004",
		"distinguishedName":             "CN=svc-web,OU=x,DC=corp,DC=local",
		"name":                          "svc-web",
		"samAccountName":                "svc-web$",
		"sid":                           "S-1-5-21-1-2-3-2001",
		"dnsHostName":                   "svc-web.corp.local",
		"description":                   "",
		"displayName":                   "",
		"enabled":                       true,
		"trustedForDelegation":          false,
		"principalsAllowed":             []string{},
		"servicePrincipalNames":         []string{},
		"kerberosEncryptionType":        []string{"AES256"},
		"managedPasswordIntervalInDays": 30,
		"accountExpirationDate":         nil,
	}
}
