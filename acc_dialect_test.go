//go:build acc

// Package adpwsh_test's acceptance suite for the PSOpenAD dialect.
//
// Everything in the ordinary suite proves the fragments compose and that the Go
// side selects them. Nothing there proves they are correct: the fake answers at
// the JSON envelope level and does not model the cmdlet layer, which is
// precisely the layer this dialect replaces. These tests run against a real
// domain.
//
// Required:
//
//	AD_ACC_SERVER     a domain controller, e.g. s-server.corp.local
//	AD_ACC_CONTAINER  a container the suite may create and destroy objects in
//
// Optional:
//
//	AD_ACC_PWSH_PATH    the pwsh executable (default "pwsh")
//	AD_ACC_DIALECT      "psopenad" (default) or "adws"
//	AD_ACC_CONCURRENCY  simultaneous pwsh processes (default 16)
//	AD_ACC_LARGE_COUNT  members in the ranged-retrieval suite (default 2000)
//
// The cross-dialect comparison lives in acc_differential_test.go and takes its
// own variables.
package adpwsh_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/local"
)

// accEnv reads a required acceptance variable. Following the harness convention
// in the provider, a missing required variable is fatal rather than a skip: a
// silently skipped acceptance run reports success having proven nothing.
func accEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s must be set to run the acceptance suite", name)
	}
	return v
}

func accDialect(t *testing.T) adpwsh.Dialect {
	t.Helper()
	switch v := os.Getenv("AD_ACC_DIALECT"); v {
	case "", "psopenad":
		return adpwsh.DialectPSOpenAD
	case "adws":
		return adpwsh.DialectADWS
	default:
		t.Fatalf("AD_ACC_DIALECT=%q: want \"psopenad\" or \"adws\"", v)
		return 0
	}
}

func accClient(t *testing.T) *adpwsh.Client {
	t.Helper()
	pwsh := os.Getenv("AD_ACC_PWSH_PATH")
	if pwsh == "" {
		pwsh = "pwsh"
	}
	// Each operation is its own pwsh process and the default bound is 4, which
	// makes a few-thousand-object suite take hours. The lab DC handles more.
	conc := 16
	if v := os.Getenv("AD_ACC_CONCURRENCY"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &conc); err != nil {
			t.Fatalf("AD_ACC_CONCURRENCY=%q: %v", v, err)
		}
	}
	tr, err := local.New(local.Config{PwshPath: pwsh, Concurrency: conc})
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	c, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport: tr,
		Server:    accEnv(t, "AD_ACC_SERVER"),
		Dialect:   accDialect(t),
	})
	if err != nil {
		t.Fatalf("adpwsh.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// accName gives each object a unique, sweepable name.
func accName(prefix string) string {
	return fmt.Sprintf("tfacc-%s-%d", prefix, time.Now().UnixNano()%1e9)
}

// accShortName is accName for classes whose sAMAccountName AD caps at 15
// characters - computers and gMSAs. A longer one is refused with
// 00000523 ERROR_INVALID_ACCOUNTNAME.
func accShortName(prefix string) string {
	return fmt.Sprintf("tfa%s%d", prefix, time.Now().UnixNano()%1e6)
}

func accContainer(t *testing.T) string { return accEnv(t, "AD_ACC_CONTAINER") }

func TestAccOULifecycle(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)
	name := accName("ou")

	desc := "created by the acceptance suite"
	ou, err := c.OU.Create(ctx, adpwsh.OUSpec{
		Name: name, Container: accContainer(t), Description: &desc,
	})
	if err != nil {
		t.Fatalf("OU.Create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.OU.Delete(context.Background(), adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true})
	})

	if ou.Name != name {
		t.Errorf("Name = %q, want %q", ou.Name, name)
	}
	if ou.Description != desc {
		t.Errorf("Description = %q, want %q", ou.Description, desc)
	}

	got, err := c.OU.Get(ctx, adpwsh.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("OU.Get: %v", err)
	}
	if got.GUID != ou.GUID || got.DN != ou.DN {
		t.Errorf("read-back mismatch: got %+v, want %+v", got, ou)
	}
}

func TestAccGroupLifecycle(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)
	name := accName("grp")

	g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: name, SamAccountName: name, Container: accContainer(t),
		Scope: adpwsh.GroupScopeGlobal, Category: adpwsh.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Group.Create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Group.Delete(context.Background(), adpwsh.ByGUID(g.GUID))
	})

	if g.Scope != adpwsh.GroupScopeGlobal {
		t.Errorf("Scope = %q, want global", g.Scope)
	}
	if g.Category != adpwsh.GroupCategorySecurity {
		t.Errorf("Category = %q, want security", g.Category)
	}
	if g.SID == "" {
		t.Error("SID is empty")
	}
}

func TestAccUserLifecycle(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)
	name := accName("usr")

	// The password must not contain the sAMAccountName: AD's complexity
	// rule rejects a password containing the account name.
	pw := adpwsh.NewSecret("Zq7!vMx2Lp#9Tr4W")
	enabled := true
	u, err := c.User.Create(ctx, adpwsh.UserSpec{
		SamAccountName: name, Container: accContainer(t),
		Password: &pw, Enabled: &enabled,
	})
	if err != nil {
		t.Fatalf("User.Create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.User.Delete(context.Background(), adpwsh.ByGUID(u.GUID))
	})

	if !u.Enabled {
		t.Error("user should be enabled: the password is written before ACCOUNTDISABLE clears")
	}
	if u.SID == "" {
		t.Error("SID is empty")
	}
}

// The ranged-retrieval proof. The failure mode is silent under-reporting rather
// than an error, which makes this the single most important assertion here.
// AD truncates a multivalued attribute at MaxValRange, 1500 by default, so the
// count has to exceed that for the test to mean anything.
//
// Each operation is its own pwsh process, so the members are created through a
// bounded worker pool; sequentially this would take hours rather than minutes.
func TestAccLargeGroupMembership(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)
	count := 2000
	if v := os.Getenv("AD_ACC_LARGE_COUNT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &count); err != nil {
			t.Fatalf("AD_ACC_LARGE_COUNT=%q: %v", v, err)
		}
	}
	if count <= 1500 {
		t.Logf("warning: %d is at or below AD's default MaxValRange of 1500, "+
			"so this run does not exercise ranged retrieval", count)
	}

	// A user's sAMAccountName is capped at 20 characters, so the members get a
	// short prefix; a longer one is refused with 00000523
	// ERROR_INVALID_ACCOUNTNAME.
	gname := accShortName("lg")
	mprefix := gname
	g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
		Name: gname, SamAccountName: gname, Container: accContainer(t),
		Scope: adpwsh.GroupScopeGlobal, Category: adpwsh.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Group.Create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Group.Delete(context.Background(), adpwsh.ByGUID(g.GUID))
	})

	type made struct {
		idx  int
		guid string
		err  error
	}
	const workers = 16
	jobs := make(chan int)
	results := make(chan made, count)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				uname := fmt.Sprintf("%sm%04d", mprefix, i)
				u, err := c.User.Create(ctx, adpwsh.UserSpec{
					SamAccountName: uname, Container: accContainer(t),
				})
				if err != nil {
					results <- made{idx: i, err: err}
					continue
				}
				results <- made{idx: i, guid: u.GUID}
			}
		}()
	}
	go func() {
		for i := 0; i < count; i++ {
			jobs <- i
		}
		close(jobs)
	}()
	go func() { wg.Wait(); close(results) }()

	members := make([]adpwsh.Identity, 0, count)
	for r := range results {
		if r.err != nil {
			t.Fatalf("User.Create %d: %v", r.idx, r.err)
		}
		members = append(members, adpwsh.ByGUID(r.guid))
	}
	// Cleanup runs its functions one after another, so registering one delete
	// per member would take as long again as the creates did - at a few
	// thousand members, hours. They are torn down through the same pool.
	t.Cleanup(func() {
		ctx := context.Background()
		del := make(chan adpwsh.Identity)
		var dwg sync.WaitGroup
		for w := 0; w < workers; w++ {
			dwg.Add(1)
			go func() {
				defer dwg.Done()
				for id := range del {
					_ = c.User.Delete(ctx, id)
				}
			}()
		}
		for _, m := range members {
			del <- m
		}
		close(del)
		dwg.Wait()
	})
	if len(members) != count {
		t.Fatalf("created %d members, want %d", len(members), count)
	}

	if err := c.Group.AddMembers(ctx, adpwsh.ByGUID(g.GUID), members); err != nil {
		t.Fatalf("AddMembers: %v", err)
	}

	got, err := c.Group.Members(ctx, adpwsh.ByGUID(g.GUID))
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != count {
		t.Fatalf("Members returned %d of %d: ranged retrieval is under-reporting", len(got), count)
	}
	for _, m := range got {
		if m.GUID == "" || m.SID == "" {
			t.Fatalf("member decoded with an empty GUID or SID: %+v", m)
		}
	}
}

// The six behaviours only a real DC can settle. Each was an open question while
// the fragments were written; this records the answer.
func TestAccDialectOpenQuestions(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)

	// dclist has no public API - it is reached only through the replication
	// wait - so it is verified by running the fragment directly against the
	// domain rather than from here. See docs/reuse-assessment.md.

	t.Run("OneLevel child detection", func(t *testing.T) {
		// ou_delete counts children with a OneLevel search and filters the base
		// DN out, because PSOpenAD's OneLevel may include it while the AD
		// cmdlets' does not. An empty OU must therefore delete cleanly: if the
		// base leaked into the count, this fails with a child count of 1.
		name := accName("ou1l")
		ou, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: name, Container: accContainer(t)})
		if err != nil {
			t.Fatalf("OU.Create: %v", err)
		}
		if err := c.OU.Delete(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true}); err != nil {
			t.Fatalf("deleting an empty OU failed, so the OneLevel base filter is wrong: %v", err)
		}
	})

	t.Run("an object-typed ACE round-trips", func(t *testing.T) {
		// A delegation ACE differs from a full-control one only in its
		// objectType, so losing that GUID would silently widen the grant.
		ref := adpwsh.SchemaRef{Kind: adpwsh.RefAttribute, Name: "description"}
		res, err := c.Schema.Resolve(ctx, []adpwsh.SchemaRef{ref})
		if err != nil {
			t.Fatalf("Schema.Resolve: %v", err)
		}
		objType := res[ref]

		name := accName("ouacl")
		ou, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: name, Container: accContainer(t)})
		if err != nil {
			t.Fatalf("OU.Create: %v", err)
		}
		t.Cleanup(func() {
			_ = c.OU.Delete(context.Background(), adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true})
		})

		// S-1-5-11 is Authenticated Users: always present, never a real grant
		// worth keeping, and removed again below.
		want := adpwsh.ACE{
			Trustee:     "S-1-5-11",
			Type:        adpwsh.ACEAllow,
			Rights:      []adpwsh.Right{"ReadProperty", "WriteProperty"},
			ObjectType:  objType,
			Inheritance: adpwsh.InheritanceDescendants,
		}
		if err := c.ACL.Grant(ctx, adpwsh.ByGUID(ou.GUID), []adpwsh.ACE{want}); err != nil {
			t.Fatalf("ACL.Grant: %v", err)
		}

		aces, err := c.ACL.Get(ctx, adpwsh.ByGUID(ou.GUID))
		if err != nil {
			t.Fatalf("ACL.Get: %v", err)
		}
		var found *adpwsh.ACE
		for i := range aces {
			a := aces[i]
			if a.Trustee == want.Trustee && a.ObjectType == objType && !a.Inherited {
				found = &aces[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("the granted ACE did not read back with objectType %s; got %d ACEs", objType, len(aces))
		}
		if found.Inheritance != adpwsh.InheritanceDescendants {
			t.Errorf("Inheritance = %q, want %q", found.Inheritance, adpwsh.InheritanceDescendants)
		}
		if found.Type != adpwsh.ACEAllow {
			t.Errorf("Type = %q, want Allow", found.Type)
		}

		if err := c.ACL.Revoke(ctx, adpwsh.ByGUID(ou.GUID), []adpwsh.ACE{want}); err != nil {
			t.Fatalf("ACL.Revoke: %v", err)
		}
		after, err := c.ACL.Get(ctx, adpwsh.ByGUID(ou.GUID))
		if err != nil {
			t.Fatalf("ACL.Get after revoke: %v", err)
		}
		for _, a := range after {
			if a.Trustee == want.Trustee && a.ObjectType == objType && !a.Inherited {
				t.Error("the ACE survived the revoke")
			}
		}
	})

	t.Run("OU protection survives a move", func(t *testing.T) {
		// Protection is a Deny of Delete, and a move is authorised through that
		// same right, so it must be lifted before the move and reapplied after.
		parent := accName("ouparent")
		pou, err := c.OU.Create(ctx, adpwsh.OUSpec{Name: parent, Container: accContainer(t)})
		if err != nil {
			t.Fatalf("OU.Create parent: %v", err)
		}
		t.Cleanup(func() {
			_ = c.OU.Delete(context.Background(), adpwsh.ByGUID(pou.GUID), adpwsh.DeleteOptions{Unprotect: true})
		})

		name := accName("oumove")
		protected := true
		ou, err := c.OU.Create(ctx, adpwsh.OUSpec{
			Name: name, Container: accContainer(t), Protected: &protected,
		})
		if err != nil {
			t.Fatalf("OU.Create: %v", err)
		}
		t.Cleanup(func() {
			_ = c.OU.Delete(context.Background(), adpwsh.ByGUID(ou.GUID), adpwsh.DeleteOptions{Unprotect: true})
		})
		if !ou.Protected {
			t.Fatal("Protected was requested on create but did not stick")
		}

		moved, err := c.OU.Update(ctx, adpwsh.ByGUID(ou.GUID), adpwsh.OUSpec{
			Name: name, Container: pou.DN, Protected: &protected,
		})
		if err != nil {
			t.Fatalf("OU.Update (move of a protected OU): %v", err)
		}
		if !moved.Protected {
			t.Error("protection was not reapplied after the move")
		}
		if !strings.EqualFold(moved.Container, pou.DN) {
			t.Errorf("Container = %q, want %q", moved.Container, pou.DN)
		}
	})

	t.Run("group scope conversion global to universal to domainlocal", func(t *testing.T) {
		// AD refuses global <-> domainlocal directly; universal is the required
		// intermediate. The DC enforces that, and the dialect does not
		// pre-validate it.
		name := accName("gscope")
		g, err := c.Group.Create(ctx, adpwsh.GroupSpec{
			Name: name, SamAccountName: name, Container: accContainer(t),
			Scope: adpwsh.GroupScopeGlobal, Category: adpwsh.GroupCategorySecurity,
		})
		if err != nil {
			t.Fatalf("Group.Create: %v", err)
		}
		t.Cleanup(func() { _ = c.Group.Delete(context.Background(), adpwsh.ByGUID(g.GUID)) })

		spec := adpwsh.GroupSpec{
			Name: name, SamAccountName: name, Container: accContainer(t),
			Category: adpwsh.GroupCategorySecurity,
		}
		for _, want := range []adpwsh.GroupScope{adpwsh.GroupScopeUniversal, adpwsh.GroupScopeDomainLocal} {
			spec.Scope = want
			got, err := c.Group.Update(ctx, adpwsh.ByGUID(g.GUID), spec)
			if err != nil {
				t.Fatalf("Group.Update to %s: %v", want, err)
			}
			if got.Scope != want {
				t.Fatalf("Scope = %q, want %q", got.Scope, want)
			}
		}
	})

	t.Run("CannotChangePassword round-trips", func(t *testing.T) {
		// canChangePassword is read from Deny ACEs on the change-password
		// extended right, and written as the same pair of ACEs Set-ADUser
		// writes - Everyone and Principal Self. Nothing else exercises the
		// write side, and a flag that reads back wrong is invisible until a
		// user cannot change their password.
		name := accShortName("cp")
		pw := adpwsh.NewSecret("Zq7!vMx2Lp#9Tr4W")
		enabled := true
		cannot := false
		u, err := c.User.Create(ctx, adpwsh.UserSpec{
			SamAccountName: name, Container: accContainer(t),
			Password: &pw, Enabled: &enabled, CanChangePassword: &cannot,
		})
		if err != nil {
			t.Fatalf("User.Create: %v", err)
		}
		t.Cleanup(func() { _ = c.User.Delete(context.Background(), adpwsh.ByGUID(u.GUID)) })
		if u.CanChangePassword {
			t.Error("CanChangePassword=false was requested on create but reads back true")
		}

		allow := true
		back, err := c.User.Update(ctx, adpwsh.ByGUID(u.GUID), adpwsh.UserSpec{
			SamAccountName: name, Container: accContainer(t),
			Enabled: &enabled, CanChangePassword: &allow,
		})
		if err != nil {
			t.Fatalf("User.Update: %v", err)
		}
		if !back.CanChangePassword {
			t.Error("CanChangePassword=true was requested on update but reads back false")
		}
	})

	t.Run("schema_resolve emits canonical GUIDs", func(t *testing.T) {
		ref := adpwsh.SchemaRef{Kind: adpwsh.RefAttribute, Name: "description"}
		got, err := c.Schema.Resolve(ctx, []adpwsh.SchemaRef{ref})
		if err != nil {
			t.Fatalf("Schema.Resolve: %v", err)
		}
		v := got[ref]
		if len(v) != 36 || strings.Count(v, "-") != 4 {
			t.Errorf("schemaIDGUID %q is not in canonical 8-4-4-4-12 form; ACL object types would break", v)
		}
		t.Logf("description schemaIDGUID = %s", v)
	})
}
