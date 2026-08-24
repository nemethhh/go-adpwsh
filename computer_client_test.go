package adpwsh_test

import (
	"context"
	"errors"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

// computerData mirrors gmsaData (serviceaccount_test.go): a full computerJSON
// shaped response for the tests that drive fake.New directly rather than
// fake.NewDirectory, so the create/read handler can return something Convert
// -AdComputer-shaped without touching the in-memory directory.
func computerData() map[string]any {
	return map[string]any{
		"objectGUID":                 "dd44ee55-0000-0000-0000-000000000005",
		"distinguishedName":          "CN=WEB01,OU=x,DC=corp,DC=local",
		"name":                       "WEB01",
		"samAccountName":             "WEB01$",
		"sid":                        "S-1-5-21-1-2-3-3001",
		"enabled":                    true,
		"dnsHostName":                "web01.corp.local",
		"description":                "",
		"displayName":                "",
		"location":                   "",
		"managedBy":                  "",
		"trustedForDelegation":       false,
		"servicePrincipalNames":      []string{},
		"allowedToDelegateTo":        []string{},
		"principalsAllowed":          []string{},
		"kerberosEncryptionType":     []string{},
		"accountExpirationDate":      nil,
		"operatingSystem":            "",
		"operatingSystemVersion":     "",
		"operatingSystemServicePack": "",
	}
}

// TestComputerClientCreateGet drives a full create -> read round trip against
// fake.Directory, mirroring TestServiceAccountCreateGet.
func TestComputerClientCreateGet(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})

	c, err := client.Computer.Create(context.Background(), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("web01.corp.local"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// AD itself appends the trailing "$" to a computer's sAMAccountName.
	if c.SamAccountName != "WEB01$" {
		t.Fatalf("sam = %q, want WEB01$", c.SamAccountName)
	}
	if c.DNSHostName != "web01.corp.local" || c.Container != "OU=x,DC=corp,DC=local" {
		t.Fatalf("created computer = %+v", c)
	}

	got, err := client.Computer.Get(context.Background(), adpwsh.ByGUID(c.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GUID != c.GUID || got.SamAccountName != "WEB01$" || got.DNSHostName != "web01.corp.local" {
		t.Fatalf("Get round trip = %+v, want match of %+v", got, c)
	}
}

// TestComputerClientCreateSendsThePinnedSplatKeys locks the create payload to
// the exact keys the fake and the real New-ADComputer cmdlet both expect:
// PrincipalsAllowedToDelegateToAccount (RBCD) through identityArgs, SPNs as a
// plain list on create (the {Replace:...} hashtable form is Update-only,
// mirroring gMSA's ServicePrincipalNames precedent), msDS-AllowedToDelegateTo
// riding under -OtherAttributes rather than a bare -AllowedToDelegateTo
// parameter (lab-verified: New-ADComputer has no such parameter and rejects
// it), and OperatingSystem* never appearing since they are read-only and not
// on ComputerSpec.
func TestComputerClientCreateSendsThePinnedSplatKeys(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "computer_create":
			create, _ = c.Payload["create"].(map[string]any)
			return fake.OK(computerData())
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	spns := []string{"HOST/web01"}
	atdt := []string{"HTTP/db01.corp.local"}
	kerb := []string{"AES256"}
	_, err := client.Computer.Create(context.Background(), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01",
		Container: "OU=x,DC=corp,DC=local", DNSHostName: adpwsh.String("web01.corp.local"),
		Description: adpwsh.String("front end"), DisplayName: adpwsh.String("Web Front End"),
		Location: adpwsh.String("DC1/Rack1"), ManagedBy: adpwsh.String("CN=Alice,OU=x,DC=corp,DC=local"),
		Enabled: adpwsh.Bool(true), TrustedForDelegation: adpwsh.Bool(false),
		ServicePrincipalNames: &spns, AllowedToDelegateTo: &atdt,
		PrincipalsAllowed:      []adpwsh.Identity{adpwsh.ByGUID("22222222-2222-2222-2222-222222222222")},
		KerberosEncryptionType: &kerb,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if create["Name"] != "WEB01" || create["SamAccountName"] != "WEB01" ||
		create["Path"] != "OU=x,DC=corp,DC=local" || create["DNSHostName"] != "web01.corp.local" {
		t.Fatalf("create splat base = %v", create)
	}
	if create["Description"] != "front end" || create["DisplayName"] != "Web Front End" ||
		create["Location"] != "DC1/Rack1" || create["ManagedBy"] != "CN=Alice,OU=x,DC=corp,DC=local" {
		t.Errorf("create splat optional strings = %v", create)
	}
	if create["Enabled"] != true || create["TrustedForDelegation"] != false {
		t.Errorf("create splat booleans = %v", create)
	}
	principals := toStrs(create["PrincipalsAllowedToDelegateToAccount"])
	if len(principals) != 1 || principals[0] != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("PrincipalsAllowedToDelegateToAccount = %v, want the one GUID via identityArgs", create["PrincipalsAllowedToDelegateToAccount"])
	}
	spnGot := toStrs(create["ServicePrincipalNames"])
	if len(spnGot) != 1 || spnGot[0] != "HOST/web01" {
		t.Errorf("ServicePrincipalNames = %v, want a plain list", create["ServicePrincipalNames"])
	}
	if _, present := create["AllowedToDelegateTo"]; present {
		t.Errorf("create splat must never carry a bare AllowedToDelegateTo key: "+
			"New-ADComputer has no such parameter (lab-verified) = %v", create)
	}
	otherAttrs, _ := create["OtherAttributes"].(map[string]any)
	atdtGot := toStrs(otherAttrs["msDS-AllowedToDelegateTo"])
	if len(atdtGot) != 1 || atdtGot[0] != "HTTP/db01.corp.local" {
		t.Errorf("OtherAttributes[msDS-AllowedToDelegateTo] = %v, want a plain list under -OtherAttributes", otherAttrs)
	}
	kerbGot := toStrs(create["KerberosEncryptionType"])
	if len(kerbGot) != 1 || kerbGot[0] != "AES256" {
		t.Errorf("KerberosEncryptionType = %v, want a plain list", create["KerberosEncryptionType"])
	}
	for _, k := range []string{"OperatingSystem", "OperatingSystemVersion", "OperatingSystemServicePack"} {
		if _, present := create[k]; present {
			t.Errorf("create splat must never carry read-only %s", k)
		}
	}
}

// TestComputerClientUpdateDelete drives a full update -> delete round trip
// against fake.Directory, mirroring TestServiceAccountUpdateDelete. It
// exercises clear-via-empty-string (Description), a full SPN replace, a full
// AllowedToDelegateTo replace (msDS-AllowedToDelegateTo via the generic
// -Replace mechanism, not a bare cmdlet parameter), a full KerberosEncryptionType
// replace, a full RBCD principals replace, flipping Enabled/TrustedForDelegation,
// and finally a combined rename+move (GUID must survive, DN must reflect the
// new CN and container) followed by Delete and a not-found Get.
func TestComputerClientUpdateDelete(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})
	ctx := context.Background()

	c, err := client.Computer.Create(ctx, adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: "OU=x,DC=corp,DC=local",
		DNSHostName: adpwsh.String("web01.corp.local"), Description: adpwsh.String("orig"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	spns := []string{"HOST/web01.corp.local"}
	atdt := []string{"HTTP/db01.corp.local"}
	kerb := []string{"AES256"}
	principal := adpwsh.ByGUID("22222222-2222-2222-2222-222222222222")
	upd, err := client.Computer.Update(ctx, adpwsh.ByGUID(c.GUID), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: "OU=x,DC=corp,DC=local",
		DNSHostName: adpwsh.String("web01.corp.local"), Description: adpwsh.String(""),
		ServicePrincipalNames: &spns, AllowedToDelegateTo: &atdt, KerberosEncryptionType: &kerb,
		PrincipalsAllowed: []adpwsh.Identity{principal},
		Enabled:           adpwsh.Bool(false), TrustedForDelegation: adpwsh.Bool(true),
	})
	if err != nil {
		t.Fatalf("Update (clear description, replace SPNs/ATDT/Kerberos/principals): %v", err)
	}
	if upd.Description != "" {
		t.Fatalf("description not cleared: %q", upd.Description)
	}
	if len(upd.ServicePrincipalNames) != 1 || upd.ServicePrincipalNames[0] != "HOST/web01.corp.local" {
		t.Fatalf("ServicePrincipalNames = %v, want a single full replace", upd.ServicePrincipalNames)
	}
	if len(upd.AllowedToDelegateTo) != 1 || upd.AllowedToDelegateTo[0] != "HTTP/db01.corp.local" {
		t.Fatalf("AllowedToDelegateTo = %v, want a single full replace", upd.AllowedToDelegateTo)
	}
	if len(upd.KerberosEncryptionType) != 1 || upd.KerberosEncryptionType[0] != "AES256" {
		t.Fatalf("KerberosEncryptionType = %v, want a single full replace", upd.KerberosEncryptionType)
	}
	if len(upd.PrincipalsAllowed) != 1 || upd.PrincipalsAllowed[0] != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("PrincipalsAllowed = %v, want the one RBCD principal", upd.PrincipalsAllowed)
	}
	if upd.Enabled != false || upd.TrustedForDelegation != true {
		t.Fatalf("Enabled/TrustedForDelegation = %v/%v, want false/true", upd.Enabled, upd.TrustedForDelegation)
	}

	// Clearing AllowedToDelegateTo and ServicePrincipalNames back to empty
	// must actually empty them, not leave the previous replace in place.
	empty := []string{}
	upd, err = client.Computer.Update(ctx, adpwsh.ByGUID(c.GUID), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: "OU=x,DC=corp,DC=local",
		DNSHostName:           adpwsh.String("web01.corp.local"),
		ServicePrincipalNames: &empty, AllowedToDelegateTo: &empty,
	})
	if err != nil {
		t.Fatalf("Update (empty ATDT/SPN replace): %v", err)
	}
	if len(upd.ServicePrincipalNames) != 0 {
		t.Fatalf("ServicePrincipalNames = %v, want cleared to empty", upd.ServicePrincipalNames)
	}
	if len(upd.AllowedToDelegateTo) != 0 {
		t.Fatalf("AllowedToDelegateTo = %v, want cleared to empty", upd.AllowedToDelegateTo)
	}

	// Rename and move together: the GUID must survive, and the DN must
	// reflect both the new CN and the new container.
	upd, err = client.Computer.Update(ctx, adpwsh.ByGUID(c.GUID), adpwsh.ComputerSpec{
		Name: "WEB02", SamAccountName: "WEB01", Container: "OU=y,DC=corp,DC=local",
		DNSHostName: adpwsh.String("web01.corp.local"),
	})
	if err != nil {
		t.Fatalf("Update (rename+move): %v", err)
	}
	if upd.GUID != c.GUID {
		t.Fatalf("GUID changed across rename+move: got %q, want %q", upd.GUID, c.GUID)
	}
	if upd.Name != "WEB02" || upd.Container != "OU=y,DC=corp,DC=local" || upd.DN != "CN=WEB02,OU=y,DC=corp,DC=local" {
		t.Fatalf("renamed+moved computer = %+v", upd)
	}

	if err := client.Computer.Delete(ctx, adpwsh.ByGUID(c.GUID)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := client.Computer.Get(ctx, adpwsh.ByGUID(c.GUID)); !errors.Is(err, adpwsh.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want KindNotFound", err)
	}
}

// TestComputerClientUpdateSamAccountName pins that Update diffs
// spec.SamAccountName against current (with the AD-appended "$" stripped
// before comparing) and sends -SamAccountName only when it actually changed,
// mirroring TestServiceAccountUpdateSamAccountName.
func TestComputerClientUpdateSamAccountName(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})
	ctx := context.Background()

	c, err := client.Computer.Create(ctx, adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: "OU=x,DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.SamAccountName != "WEB01$" {
		t.Fatalf("SamAccountName after create = %q, want WEB01$", c.SamAccountName)
	}

	upd, err := client.Computer.Update(ctx, adpwsh.ByGUID(c.GUID), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB02", Container: "OU=x,DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("Update (change sam WEB01 -> WEB02): %v", err)
	}
	if upd.SamAccountName != "WEB02$" {
		t.Fatalf("SamAccountName after sam change = %q, want WEB02$", upd.SamAccountName)
	}

	// Repeating the same (already-applied, un-suffixed) sam must not error
	// and must not spuriously churn -SamAccountName.
	upd, err = client.Computer.Update(ctx, adpwsh.ByGUID(c.GUID), adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB02", Container: "OU=x,DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("Update (unchanged sam): %v", err)
	}
	if upd.SamAccountName != "WEB02$" {
		t.Fatalf("SamAccountName after unchanged-sam update = %q, want WEB02$ (no churn)", upd.SamAccountName)
	}
}

// TestComputerClientSearchOverFake exercises Search's class-scoped read
// against fake.Directory, mirroring TestServiceAccountSearchOverFake.
func TestComputerClientSearchOverFake(t *testing.T) {
	dir := fake.NewDirectory()
	client := mustClient(t, adpwsh.Config{Transport: dir.Transport()})
	ctx := context.Background()

	a, err := client.Computer.Create(ctx, adpwsh.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: "OU=x,DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("create WEB01: %v", err)
	}
	if _, err := client.Computer.Create(ctx, adpwsh.ComputerSpec{
		Name: "WEB02", SamAccountName: "WEB02", Container: "OU=y,DC=corp,DC=local",
	}); err != nil {
		t.Fatalf("create WEB02: %v", err)
	}

	got, err := client.Computer.Search(ctx, adpwsh.Query{
		SearchBase: "OU=x,DC=corp,DC=local", Scope: adpwsh.SearchScopeOneLevel,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].GUID != a.GUID {
		t.Fatalf("scoped search = %+v, want just WEB01", got)
	}

	all, err := client.Computer.Search(ctx, adpwsh.Query{})
	if err != nil {
		t.Fatalf("Search (subtree): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("subtree search = %d results, want 2", len(all))
	}
}
