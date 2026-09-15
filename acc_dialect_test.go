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
//	AD_ACC_PWSH_PATH  the pwsh executable (default "pwsh")
//	AD_ACC_DIALECT    "psopenad" (default) or "adws"
package adpwsh_test

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	tr, err := local.New(local.Config{PwshPath: pwsh})
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
func TestAccLargeGroupMembership(t *testing.T) {
	ctx := context.Background()
	c := accClient(t)
	count := 2000
	if v := os.Getenv("AD_ACC_LARGE_COUNT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &count); err != nil {
			t.Fatalf("AD_ACC_LARGE_COUNT=%q: %v", v, err)
		}
	}

	gname := accName("lgrp")
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

	members := make([]adpwsh.Identity, 0, count)
	for i := 0; i < count; i++ {
		uname := fmt.Sprintf("%s-m%04d", gname, i)
		u, err := c.User.Create(ctx, adpwsh.UserSpec{
			SamAccountName: uname, Container: accContainer(t),
		})
		if err != nil {
			t.Fatalf("User.Create %d: %v", i, err)
		}
		guid := u.GUID
		t.Cleanup(func() {
			_ = c.User.Delete(context.Background(), adpwsh.ByGUID(guid))
		})
		members = append(members, adpwsh.ByGUID(u.GUID))
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
