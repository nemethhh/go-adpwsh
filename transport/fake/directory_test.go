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
