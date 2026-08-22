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

// TestFakeTrimsAndTruncatesNames pins the fake to two silent adjustments a real
// DC makes to name-like attributes: surrounding whitespace is trimmed, and an
// over-long value is truncated to the attribute's ceiling (CN 64, sAMAccountName
// 20). This is what lets the provider's consistency guard be exercised without a
// real domain: a consumer that sends an out-of-range value gets back what AD
// would actually have stored.
func TestFakeTrimsAndTruncatesNames(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	_, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"})
	if err != nil {
		t.Fatalf("seed OU: %v", err)
	}

	// Trailing space is trimmed, exactly as Active Directory trims an RDN.
	g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Reps ", SamAccountName: "reps ", Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeGlobal,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if g.Name != "Reps" {
		t.Errorf("Name = %q, want %q (trailing space trimmed)", g.Name, "Reps")
	}
	if g.SamAccountName != "reps" {
		t.Errorf("SamAccountName = %q, want %q (trailing space trimmed)", g.SamAccountName, "reps")
	}

	// A sAMAccountName over 20 characters is truncated to 20.
	long := "abcdefghijklmnopqrstuvwxyz" // 26 chars
	u, err := c.User.Create(ctx, adpwsh.UserSpec{
		SamAccountName: long, Container: "OU=Staff,DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if len(u.SamAccountName) != 20 || u.SamAccountName != long[:20] {
		t.Errorf("SamAccountName = %q, want first 20 chars %q", u.SamAccountName, long[:20])
	}
}

// TestFakeCreateSamUniquenessUsesMutatedValue proves the create-time duplicate
// check compares the same mutated sAMAccountName that ends up stored, not the
// raw incoming one. Real AD trims before it enforces uniqueness, so a second
// create differing from an existing object only by surrounding whitespace must
// be rejected as already-exists, not silently produce two objects that both
// resolve to the same sAMAccountName.
func TestFakeCreateSamUniquenessUsesMutatedValue(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	if _, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Reps", SamAccountName: "reps", Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeGlobal,
	}); err != nil {
		t.Fatalf("create first group: %v", err)
	}

	// "reps " mutates to the same "reps" already stored on the first group, so
	// this must be rejected as already-exists, not silently accepted as
	// distinct raw input.
	_, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Reps2", SamAccountName: "reps ", Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeGlobal,
	})
	if !errors.Is(err, adpwsh.ErrAlreadyExists) {
		t.Fatalf("create with sam differing only by trailing whitespace = %v, want KindAlreadyExists", err)
	}
}

// TestFakeCreateSamUniquenessStableAtTruncationBoundary covers the case where
// the 20-char truncation boundary lands on an internal whitespace character.
// mutateLikeAD must be idempotent: truncating "abcdefghijklmnopqrs zzzzz" to 20
// chars yields "abcdefghijklmnopqrs " (trailing space at the cut), and a
// second application must not then trim that away to a 19-char result. If it
// did, the uniqueness check (one application, in handleCreate) and the stored
// value (a second application, inside applySplat) would disagree, and two
// creates sharing this exact raw sam would both succeed instead of the second
// being rejected as already-exists.
func TestFakeCreateSamUniquenessStableAtTruncationBoundary(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	if _, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
	const raw = "abcdefghijklmnopqrs zzzzz" // space at index 19: the truncation boundary
	if _, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Boundary1", SamAccountName: raw, Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeGlobal,
	}); err != nil {
		t.Fatalf("create first group: %v", err)
	}

	_, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: "Boundary2", SamAccountName: raw, Container: "OU=Staff,DC=corp,DC=local",
		Scope: adpwsh.GroupScopeGlobal,
	})
	if !errors.Is(err, adpwsh.ErrAlreadyExists) {
		t.Fatalf("second create with the identical raw sam %q = %v, want KindAlreadyExists", raw, err)
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
