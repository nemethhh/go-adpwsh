package fake_test

import (
	"context"
	"errors"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func newClient(t *testing.T) (*adpwsh.Client, *fake.Directory) {
	t.Helper()
	dir := fake.NewDirectory()
	c, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: dir.Transport()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, dir
}

func TestDirectoryFullOULifecycle(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	ou, err := c.OU.Create(ctx, adpwsh.OUSpec{
		Name: "Staff", Container: "DC=corp,DC=local", Description: adpwsh.String("staff"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ou.DN != "OU=Staff,DC=corp,DC=local" || ou.Description != "staff" || !ou.Protected {
		t.Fatalf("created ou = %+v", ou)
	}

	got, err := c.OU.Get(ctx, adpwsh.ByGUID(ou.GUID))
	if err != nil || got.DN != ou.DN {
		t.Fatalf("Get: %+v %v", got, err)
	}

	moved, err := c.OU.Update(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.OUSpec{
		Name: "People", Container: "DC=corp,DC=local", Description: adpwsh.String(""),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if moved.Name != "People" || moved.DN != "OU=People,DC=corp,DC=local" || moved.Description != "" {
		t.Fatalf("updated ou = %+v", moved)
	}

	if err := c.OU.Delete(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.OU.Get(ctx, adpwsh.ByGUID(ou.GUID)); !errors.Is(err, adpwsh.ErrNotFound) {
		t.Fatalf("after delete, Get = %v, want KindNotFound", err)
	}
}

// A name containing a comma is one RDN, not two. Concatenating it into a DN
// produces a string whose parent parses as "EMEA,DC=corp,DC=local", so the
// object reads back as living somewhere it does not — and a consumer that
// nests anything under it inherits the wrong container.
func TestDirectoryEscapesACommaInAnRDN(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	ou, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Sales, EMEA", Container: "DC=corp,DC=local"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if want := `OU=Sales\, EMEA,DC=corp,DC=local`; ou.DN != want {
		t.Errorf("DN = %q, want %q", ou.DN, want)
	}
	if ou.Container != "DC=corp,DC=local" {
		t.Errorf("Container = %q, want DC=corp,DC=local", ou.Container)
	}

	// The escaped DN must still work as another object's container.
	g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Reps", SamAccountName: "reps", Container: ou.DN, Scope: adpwsh.GroupScopeGlobal,
	})
	if err != nil {
		t.Fatalf("Group.Create in an escaped container: %v", err)
	}
	if g.Container != ou.DN {
		t.Errorf("group container = %q, want %q", g.Container, ou.DN)
	}

	// And a rename into a comma-bearing name must escape too.
	renamed, err := c.OU.Update(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.OUSpec{
		Name: "Sales, APAC", Container: "DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if want := `OU=Sales\, APAC,DC=corp,DC=local`; renamed.DN != want {
		t.Errorf("renamed DN = %q, want %q", renamed.DN, want)
	}
}

func TestDirectoryEnforcesUniquenessAndChildren(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	ou, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); !errors.Is(err, adpwsh.ErrAlreadyExists) {
		t.Fatalf("duplicate create = %v, want KindAlreadyExists", err)
	}
	if _, err := c.User.Create(ctx, adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: ou.DN,
	}); err != nil {
		t.Fatal(err)
	}
	err = c.OU.Delete(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true})
	if !errors.Is(err, adpwsh.ErrConstraint) {
		t.Fatalf("deleting a non-empty OU = %v, want KindConstraint", err)
	}
}

func TestDirectoryUserAndGroupLifecycle(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	if _, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
	pw := adpwsh.NewSecret("Correct-Horse-1")
	u, err := c.User.Create(ctx, adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
		GivenName: adpwsh.String("John"), Surname: adpwsh.String("Doe"),
		Enabled: adpwsh.Bool(true), Password: &pw,
	})
	if err != nil {
		t.Fatalf("user Create: %v", err)
	}
	if u.SID == "" || !u.Enabled || u.Surname != "Doe" {
		t.Fatalf("user = %+v", u)
	}
	// A user can also be found by sAMAccountName, which is what import uses.
	if got, err := c.User.Get(ctx, adpwsh.BySAM("jdoe")); err != nil || got.GUID != u.GUID {
		t.Fatalf("BySAM: %+v %v", got, err)
	}
	if err := c.User.SetPassword(ctx, adpwsh.ByGUID(u.GUID), adpwsh.NewSecret("Rotated-2")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	cleared, err := c.User.Update(ctx, adpwsh.ByGUID(u.GUID), adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
		Surname: adpwsh.String(""), Enabled: adpwsh.Bool(false),
	})
	if err != nil {
		t.Fatalf("user Update: %v", err)
	}
	if cleared.Surname != "" || cleared.Enabled {
		t.Fatalf("cleared user = %+v", cleared)
	}

	g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Developers", SamAccountName: "developers",
		Container: "OU=Staff,DC=corp,DC=local", Scope: adpwsh.GroupScopeGlobal,
	})
	if err != nil {
		t.Fatalf("group Create: %v", err)
	}
	if g.Scope != adpwsh.GroupScopeGlobal || g.Category != adpwsh.GroupCategorySecurity {
		t.Fatalf("group = %+v", g)
	}
	if err := c.Group.Delete(ctx, adpwsh.ByGUID(g.GUID)); err != nil {
		t.Fatalf("group Delete: %v", err)
	}
	if err := c.User.Delete(ctx, adpwsh.ByGUID(u.GUID)); err != nil {
		t.Fatalf("user Delete: %v", err)
	}
}

// A delete leaves a tombstone, so the next create of the same name reports the
// condition instead of failing opaquely.
func TestDirectoryTombstoneBlocksRecreate(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()
	if _, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
	u, err := c.User.Create(ctx, adpwsh.UserSpec{SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.User.Delete(ctx, adpwsh.ByGUID(u.GUID)); err != nil {
		t.Fatal(err)
	}
	_, err = c.User.Create(ctx, adpwsh.UserSpec{SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local"})
	if !errors.Is(err, adpwsh.ErrAlreadyExists) {
		t.Fatalf("recreate after delete = %v, want KindAlreadyExists", err)
	}
	var e *adpwsh.Error
	if !errors.As(err, &e) || !e.Tombstoned {
		t.Errorf("Tombstoned not set: %+v", e)
	}
}

func TestDirectoryMembership(t *testing.T) {
	d := fake.NewDirectory()
	g := d.Seed("group", "devs", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-1001"})
	u1 := d.Seed("user", "alice", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-1101"})
	u2 := d.Seed("user", "bob", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-1102"})

	// Add u1, u2.
	if r := d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{
		"identity": g, "members": []any{u1, u2}}}); r.Err != nil {
		t.Fatalf("add: %+v", r.Err)
	}
	// Adding u1 again is idempotent.
	if r := d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{
		"identity": g, "members": []any{u1}}}); r.Err != nil {
		t.Fatalf("idempotent add: %+v", r.Err)
	}
	// Read returns exactly two members.
	r := d.Handle(fake.Call{Op: "group_members_read", Payload: map[string]any{"identity": g}})
	members := r.Data.(map[string]any)["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("read returned %d members, want 2", len(members))
	}
	// Check: u1 is a member, a fresh unrelated object is not.
	if c := d.Handle(fake.Call{Op: "group_member_check", Payload: map[string]any{
		"group": g, "member": u1}}); c.Data.(map[string]any)["member"] != true {
		t.Errorf("u1 should be a member")
	}
	// Remove u1; then it is no longer a member; removing again is idempotent.
	if r := d.Handle(fake.Call{Op: "group_members_remove", Payload: map[string]any{
		"identity": g, "members": []any{u1}}}); r.Err != nil {
		t.Fatalf("remove: %+v", r.Err)
	}
	if c := d.Handle(fake.Call{Op: "group_member_check", Payload: map[string]any{
		"group": g, "member": u1}}); c.Data.(map[string]any)["member"] != false {
		t.Errorf("u1 should not be a member after removal")
	}
	if r := d.Handle(fake.Call{Op: "group_members_remove", Payload: map[string]any{
		"identity": g, "members": []any{u1}}}); r.Err != nil {
		t.Fatalf("idempotent remove: %+v", r.Err)
	}
	_ = u2
}

func TestDirectoryMembershipRecursive(t *testing.T) {
	d := fake.NewDirectory()
	parent := d.Seed("group", "parent", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-3001"})
	child := d.Seed("group", "child", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-3002"})
	user := d.Seed("user", "leaf", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-3101"})

	// user ∈ child, child ∈ parent, and parent ∈ child (a cycle to prove termination).
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": child, "members": []any{user}}})
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": parent, "members": []any{child}}})
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": child, "members": []any{parent}}})

	r := d.Handle(fake.Call{Op: "group_members_read_recursive", Payload: map[string]any{"identity": parent}})
	members := r.Data.(map[string]any)["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("recursive members = %d (%v), want 1 leaf user", len(members), members)
	}
	m := members[0].(map[string]any)
	if m["objectGUID"] != user {
		t.Errorf("leaf = %v, want user %s", m["objectGUID"], user)
	}
	if m["objectClass"] != "user" {
		t.Errorf("leaf class = %v, want user", m["objectClass"])
	}
}

// TestDirectoryMembershipRecursiveDedup proves a leaf reachable through more than
// one nested path (a diamond) is returned exactly once.
func TestDirectoryMembershipRecursiveDedup(t *testing.T) {
	d := fake.NewDirectory()
	parent := d.Seed("group", "parent", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-4001"})
	childA := d.Seed("group", "childA", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-4002"})
	childB := d.Seed("group", "childB", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-4003"})
	user := d.Seed("user", "shared", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-4101"})

	// parent → {childA, childB}; both children → the same user (a diamond).
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": parent, "members": []any{childA, childB}}})
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": childA, "members": []any{user}}})
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": childB, "members": []any{user}}})

	r := d.Handle(fake.Call{Op: "group_members_read_recursive", Payload: map[string]any{"identity": parent}})
	members := r.Data.(map[string]any)["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("recursive members = %d (%v), want the shared user exactly once", len(members), members)
	}
	if got := members[0].(map[string]any)["objectGUID"]; got != user {
		t.Errorf("leaf = %v, want user %s", got, user)
	}
}

// TestDirectoryMembershipRecursiveSkipsEmptyGroups pins the fake to the real
// Get-ADGroupMember -Recursive behavior confirmed on the lab: a group object is
// never returned, not even an empty nested group — only leaf user/computer
// accounts are.
func TestDirectoryMembershipRecursiveSkipsEmptyGroups(t *testing.T) {
	d := fake.NewDirectory()
	parent := d.Seed("group", "parent", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-5001"})
	empty := d.Seed("group", "empty", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-5002"})
	nonEmpty := d.Seed("group", "nonEmpty", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-5003"})
	user := d.Seed("user", "leaf", "DC=corp,DC=local", map[string]any{"sid": "S-1-5-21-1-2-3-5101"})

	// parent → {empty (no members), nonEmpty → user}.
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": nonEmpty, "members": []any{user}}})
	d.Handle(fake.Call{Op: "group_members_add", Payload: map[string]any{"identity": parent, "members": []any{empty, nonEmpty}}})

	r := d.Handle(fake.Call{Op: "group_members_read_recursive", Payload: map[string]any{"identity": parent}})
	members := r.Data.(map[string]any)["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("recursive members = %d (%v), want only the leaf user (no group objects)", len(members), members)
	}
	m := members[0].(map[string]any)
	if m["objectGUID"] != user {
		t.Errorf("leaf = %v, want user %s", m["objectGUID"], user)
	}
	if m["objectClass"] == "group" {
		t.Errorf("a group object was returned (%v); recursive must return only leaf accounts", m)
	}
}

func TestDirectoryDACLGrantIdempotentAndRevokeSpecific(t *testing.T) {
	d := fake.NewDirectory()
	guid := d.Seed("organizationalUnit", "Staff", "DC=corp,DC=local", nil)
	ace := map[string]any{"trustee": "S-1-5-1", "type": "Allow", "rights": []any{"WriteProperty"},
		"objectType": "", "inheritedObjectType": "", "inheritance": "Descendents"}
	// A second ACE with a different trustee, so its fakeACEKey differs from
	// ace's: revoking ace must leave this one behind, not clear the DACL.
	other := map[string]any{"trustee": "S-1-5-2", "type": "Allow", "rights": []any{"WriteProperty"},
		"objectType": "", "inheritedObjectType": "", "inheritance": "Descendents"}

	grant := fake.Call{Op: "acl_grant", Payload: map[string]any{"target": guid, "aces": []any{ace, ace, other}}}
	d.Handle(grant)
	d.Handle(grant) // idempotent

	read := d.Handle(fake.Call{Op: "acl_read", Payload: map[string]any{"target": guid}})
	aces, _ := read.Data.(map[string]any)["aces"].([]any)
	if len(aces) != 2 {
		t.Fatalf("after granting two distinct ACEs (one twice), dacl has %d entries, want 2", len(aces))
	}

	d.Handle(fake.Call{Op: "acl_revoke", Payload: map[string]any{"target": guid, "aces": []any{ace}}})
	read = d.Handle(fake.Call{Op: "acl_read", Payload: map[string]any{"target": guid}})
	aces, _ = read.Data.(map[string]any)["aces"].([]any)
	if len(aces) != 1 {
		t.Fatalf("after revoking one of two ACEs, dacl has %d entries, want 1", len(aces))
	}
	surviving, _ := aces[0].(map[string]any)
	if trustee, _ := surviving["trustee"].(string); trustee != "S-1-5-2" {
		t.Fatalf("surviving ACE = %v, want the untouched trustee S-1-5-2 (revoke must be specific, not clear the DACL)", surviving)
	}
}

// TestFakeGMSACreateRead pins the fake's ADServiceAccount create defaults: the
// sAMAccountName gains the trailing "$" AD itself appends, and
// managedPasswordIntervalInDays defaults to 30 when the caller does not name
// one.
func TestFakeGMSACreateRead(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "gmsa_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "svc-web", "SamAccountName": "svc-web",
			"Path": "OU=x,DC=corp,DC=local", "DNSHostName": "svc-web.corp.local",
		},
		"project": []string{"*"},
	}})
	if create.Err != nil {
		t.Fatalf("create: %+v", create.Err)
	}
	out, _ := create.Data.(map[string]any)
	guid, _ := out["objectGUID"].(string)
	if guid == "" {
		t.Fatal("no objectGUID")
	}
	if out["samAccountName"] != "svc-web$" {
		t.Fatalf("sam = %v, want svc-web$", out["samAccountName"])
	}
	if out["managedPasswordIntervalInDays"] != 30 {
		t.Fatalf("interval = %v, want 30", out["managedPasswordIntervalInDays"])
	}

	read := d.Handle(fake.Call{Op: "gmsa_read", Payload: map[string]any{"identity": guid, "project": []string{"*"}}})
	if read.Err != nil {
		t.Fatalf("read: %+v", read.Err)
	}
	got, _ := read.Data.(map[string]any)
	if got["samAccountName"] != "svc-web$" {
		t.Fatalf("sam = %v, want svc-web$", got["samAccountName"])
	}
	if got["managedPasswordIntervalInDays"] != 30 {
		t.Fatalf("interval = %v, want 30", got["managedPasswordIntervalInDays"])
	}
	if got["dnsHostName"] != "svc-web.corp.local" {
		t.Fatalf("dnsHostName = %v, want svc-web.corp.local", got["dnsHostName"])
	}
	if got["enabled"] != true {
		t.Fatalf("enabled = %v, want true", got["enabled"])
	}
	kerb, _ := got["kerberosEncryptionType"].([]string)
	if len(kerb) != 3 {
		t.Fatalf("kerberosEncryptionType = %v, want [RC4 AES128 AES256]", got["kerberosEncryptionType"])
	}
	// Every key Convert-AdServiceAccount emits must round-trip through the fake,
	// so one Go decoder handles both backends.
	for _, k := range []string{
		"objectGUID", "distinguishedName", "name", "samAccountName", "sid",
		"dnsHostName", "description", "displayName", "enabled", "trustedForDelegation",
		"principalsAllowed", "servicePrincipalNames", "kerberosEncryptionType",
		"managedPasswordIntervalInDays", "accountExpirationDate",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("read is missing key %q", k)
		}
	}
}

// TestFakeGMSAUpdateFullReplace pins the update contract the real
// Set-ADServiceAccount cmdlet family gives: PrincipalsAllowed, SPNs and the
// Kerberos encryption types are full-replace, and an empty string on a
// string attribute clears it (mirroring -Clear).
func TestFakeGMSAUpdateFullReplace(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "gmsa_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "svc", "SamAccountName": "svc",
			"Path": "OU=x,DC=corp,DC=local", "DNSHostName": "svc.corp.local",
			"Description": "orig",
		},
	}})
	if create.Err != nil {
		t.Fatalf("create: %+v", create.Err)
	}
	guid := create.Data.(map[string]any)["objectGUID"].(string)

	upd := d.Handle(fake.Call{Op: "gmsa_update", Payload: map[string]any{
		"identity": guid,
		"set": map[string]any{
			"Identity":               guid,
			"Clear":                  []any{"description"},
			"ServicePrincipalNames":  map[string]any{"Replace": []any{"HTTP/svc.corp.local"}},
			"KerberosEncryptionType": []any{"AES256"},
			"PrincipalsAllowedToRetrieveManagedPassword": []any{"11111111-1111-1111-1111-111111111111"},
			"TrustedForDelegation":                       true,
		},
	}})
	if upd.Err != nil {
		t.Fatalf("update: %+v", upd.Err)
	}
	got := upd.Data.(map[string]any)
	if got["description"] != "" {
		t.Fatalf("description = %v, want cleared", got["description"])
	}
	spn, _ := got["servicePrincipalNames"].([]string)
	if len(spn) != 1 || spn[0] != "HTTP/svc.corp.local" {
		t.Fatalf("servicePrincipalNames = %v, want [HTTP/svc.corp.local]", got["servicePrincipalNames"])
	}
	kerb, _ := got["kerberosEncryptionType"].([]string)
	if len(kerb) != 1 || kerb[0] != "AES256" {
		t.Fatalf("kerberosEncryptionType = %v, want [AES256]", got["kerberosEncryptionType"])
	}
	principals, _ := got["principalsAllowed"].([]string)
	if len(principals) != 1 || principals[0] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("principalsAllowed = %v, want the one GUID given", got["principalsAllowed"])
	}
	if got["trustedForDelegation"] != true {
		t.Fatalf("trustedForDelegation = %v, want true", got["trustedForDelegation"])
	}
	// managedPasswordIntervalInDays is create-only: absent from the update
	// payload must not crash and must not change the stored value.
	if got["managedPasswordIntervalInDays"] != 30 {
		t.Fatalf("managedPasswordIntervalInDays = %v, want unchanged 30", got["managedPasswordIntervalInDays"])
	}
}

// TestFakeGMSADeleteAndSearch exercises gmsa_delete (tombstone + not-found on
// re-read) and gmsa_search (class-scoped, returns the Convert-shaped JSON).
func TestFakeGMSADeleteAndSearch(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "gmsa_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "svc2", "SamAccountName": "svc2",
			"Path": "OU=x,DC=corp,DC=local", "DNSHostName": "svc2.corp.local",
		},
	}})
	guid := create.Data.(map[string]any)["objectGUID"].(string)

	search := d.Handle(fake.Call{Op: "gmsa_search", Payload: map[string]any{
		"filter": "(objectClass=*)", "searchBase": "DC=corp,DC=local", "scope": "Subtree", "sizeLimit": float64(1000),
	}})
	if search.Err != nil {
		t.Fatalf("search: %+v", search.Err)
	}
	results, _ := search.Data.(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}

	del := d.Handle(fake.Call{Op: "gmsa_delete", Payload: map[string]any{"identity": guid}})
	if del.Err != nil {
		t.Fatalf("delete: %+v", del.Err)
	}
	read := d.Handle(fake.Call{Op: "gmsa_read", Payload: map[string]any{"identity": guid}})
	if read.Err == nil {
		t.Fatal("read after delete: want not-found, got success")
	}
}

// TestFakeComputerCreateRead pins the fake's Computer create defaults: a
// SamAccountName the caller omits is derived from Name with the trailing "$"
// AD itself appends, Enabled defaults true (unlike a user), RBCD principals
// (PrincipalsAllowedToDelegateToAccount) are stored, and the OS-reported
// fields start empty since nothing provisions them at create.
func TestFakeComputerCreateRead(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "computer_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "WEB01", "Path": "OU=x,DC=corp,DC=local",
			"Description":                          "front end",
			"PrincipalsAllowedToDelegateToAccount": []any{"22222222-2222-2222-2222-222222222222"},
		},
		"project": []string{"*"},
	}})
	if create.Err != nil {
		t.Fatalf("create: %+v", create.Err)
	}
	out, _ := create.Data.(map[string]any)
	guid, _ := out["objectGUID"].(string)
	if guid == "" {
		t.Fatal("no objectGUID")
	}
	if out["samAccountName"] != "WEB01$" {
		t.Fatalf("sam = %v, want WEB01$ (derived from Name, caller supplied none)", out["samAccountName"])
	}
	if out["enabled"] != true {
		t.Fatalf("enabled = %v, want true (computer default, unlike user)", out["enabled"])
	}
	principals, _ := out["principalsAllowed"].([]string)
	if len(principals) != 1 || principals[0] != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("principalsAllowed = %v, want the one RBCD principal given", out["principalsAllowed"])
	}
	for _, k := range []string{"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack"} {
		if out[k] != "" {
			t.Errorf("%s = %v, want empty (nothing provisions it at create)", k, out[k])
		}
	}

	read := d.Handle(fake.Call{Op: "computer_read", Payload: map[string]any{"identity": guid, "project": []string{"*"}}})
	if read.Err != nil {
		t.Fatalf("read: %+v", read.Err)
	}
	got, _ := read.Data.(map[string]any)
	if got["samAccountName"] != "WEB01$" {
		t.Fatalf("sam on read = %v, want WEB01$", got["samAccountName"])
	}
	if got["description"] != "front end" {
		t.Fatalf("description = %v, want front end", got["description"])
	}
	// Every key Convert-AdComputer emits must round-trip through the fake, so
	// one Go decoder handles both backends.
	for _, k := range []string{
		"objectGUID", "distinguishedName", "name", "samAccountName", "sid", "enabled",
		"dnsHostName", "description", "displayName", "location", "managedBy",
		"trustedForDelegation", "servicePrincipalNames", "allowedToDelegateTo",
		"principalsAllowed", "kerberosEncryptionType", "accountExpirationDate",
		"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("read is missing key %q", k)
		}
	}
}

// TestFakeComputerUpdateFullReplace pins the update contract: SamAccountName
// still gains AD's trailing "$" on create even when the caller supplies one
// without it, ServicePrincipalNames and RBCD principals are full-replace,
// and -Clear empties a string attribute.
func TestFakeComputerUpdateFullReplace(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "computer_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "WEB02", "SamAccountName": "WEB02",
			"Path": "OU=x,DC=corp,DC=local", "Description": "orig",
		},
	}})
	if create.Err != nil {
		t.Fatalf("create: %+v", create.Err)
	}
	guid := create.Data.(map[string]any)["objectGUID"].(string)
	if create.Data.(map[string]any)["samAccountName"] != "WEB02$" {
		t.Fatalf("sam at create = %v, want WEB02$", create.Data.(map[string]any)["samAccountName"])
	}

	upd := d.Handle(fake.Call{Op: "computer_update", Payload: map[string]any{
		"identity": guid,
		"set": map[string]any{
			"Identity":                             guid,
			"Clear":                                []any{"description"},
			"ServicePrincipalNames":                map[string]any{"Replace": []any{"HOST/web02.corp.local"}},
			"PrincipalsAllowedToDelegateToAccount": []any{"33333333-3333-3333-3333-333333333333"},
			"TrustedForDelegation":                 true,
		},
	}})
	if upd.Err != nil {
		t.Fatalf("update: %+v", upd.Err)
	}
	got := upd.Data.(map[string]any)
	if got["description"] != "" {
		t.Fatalf("description = %v, want cleared", got["description"])
	}
	spn, _ := got["servicePrincipalNames"].([]string)
	if len(spn) != 1 || spn[0] != "HOST/web02.corp.local" {
		t.Fatalf("servicePrincipalNames = %v, want [HOST/web02.corp.local]", got["servicePrincipalNames"])
	}
	principals, _ := got["principalsAllowed"].([]string)
	if len(principals) != 1 || principals[0] != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("principalsAllowed = %v, want the one RBCD principal given", got["principalsAllowed"])
	}
	if got["trustedForDelegation"] != true {
		t.Fatalf("trustedForDelegation = %v, want true", got["trustedForDelegation"])
	}
	if got["samAccountName"] != "WEB02$" {
		t.Fatalf("samAccountName after update = %v, want unchanged WEB02$", got["samAccountName"])
	}
}

// TestFakeComputerDeleteAndSearch exercises computer_search (class-scoped,
// returns the Convert-shaped JSON) and computer_delete (tombstone +
// not-found on re-read).
func TestFakeComputerDeleteAndSearch(t *testing.T) {
	d := fake.NewDirectory()
	create := d.Handle(fake.Call{Op: "computer_create", Payload: map[string]any{
		"create": map[string]any{
			"Name": "WEB03", "Path": "OU=x,DC=corp,DC=local",
		},
	}})
	if create.Err != nil {
		t.Fatalf("create: %+v", create.Err)
	}
	guid := create.Data.(map[string]any)["objectGUID"].(string)

	search := d.Handle(fake.Call{Op: "computer_search", Payload: map[string]any{
		"filter": "(objectClass=*)", "searchBase": "DC=corp,DC=local", "scope": "Subtree", "sizeLimit": float64(1000),
	}})
	if search.Err != nil {
		t.Fatalf("search: %+v", search.Err)
	}
	results, _ := search.Data.(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("search results = %d, want 1", len(results))
	}

	del := d.Handle(fake.Call{Op: "computer_delete", Payload: map[string]any{"identity": guid}})
	if del.Err != nil {
		t.Fatalf("delete: %+v", del.Err)
	}
	read := d.Handle(fake.Call{Op: "computer_read", Payload: map[string]any{"identity": guid}})
	if read.Err == nil {
		t.Fatal("read after delete: want not-found, got success")
	}
}
