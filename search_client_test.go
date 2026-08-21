package adpwsh_test

import (
	"context"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func newClient(t *testing.T, dir *fake.Directory) *adpwsh.Client {
	t.Helper()
	c, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: dir.Transport()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestUserSearchScopeAndFilterOverFake(t *testing.T) {
	dir := fake.NewDirectory()
	dir.Seed("user", "alice", "OU=Sales,DC=corp,DC=local", map[string]any{
		"samAccountName": "alice", "description": "R&D", "enabled": true,
		"sid": "S-1-5-21-1", "canChangePassword": true, "passwordExpires": true,
	})
	dir.Seed("user", "bob", "OU=Eng,DC=corp,DC=local", map[string]any{
		"samAccountName": "bob", "description": "Ops", "enabled": true,
		"sid": "S-1-5-21-2", "canChangePassword": true, "passwordExpires": true,
	})
	c := newClient(t, dir)

	// OneLevel under OU=Sales returns only alice.
	got, err := c.User.Search(context.Background(), adpwsh.Query{
		SearchBase: "OU=Sales,DC=corp,DC=local", Scope: adpwsh.SearchScopeOneLevel,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].SamAccountName != "alice" {
		t.Fatalf("scope filter wrong: %+v", got)
	}

	// filter_by-style equality via the exported builder.
	got, err = c.User.Search(context.Background(), adpwsh.Query{Filter: adpwsh.Equal("description", "Ops")})
	if err != nil || len(got) != 1 || got[0].SamAccountName != "bob" {
		t.Fatalf("equality filter wrong: %+v err=%v", got, err)
	}

	// Empty result is an empty slice, not an error.
	got, err = c.User.Search(context.Background(), adpwsh.Query{Filter: adpwsh.Equal("description", "none")})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty result wrong: %+v err=%v", got, err)
	}
}

func TestSearchOverSizeErrors(t *testing.T) {
	dir := fake.NewDirectory()
	for _, n := range []string{"g1", "g2", "g3"} {
		dir.Seed("group", n, "DC=corp,DC=local", map[string]any{
			"samAccountName": n, "scope": "global", "category": "security", "sid": "S-1-5-21-" + n,
		})
	}
	c := newClient(t, dir)
	_, err := c.Group.Search(context.Background(), adpwsh.Query{SizeLimit: 2})
	if err == nil {
		t.Fatal("expected KindTooManyResults")
	}
	if !errorsIsKind(err, adpwsh.ErrTooManyResults) {
		t.Fatalf("wrong kind: %v", err)
	}
}

func errorsIsKind(err, sentinel error) bool {
	type iser interface{ Is(error) bool }
	if e, ok := err.(iser); ok {
		return e.Is(sentinel)
	}
	return false
}
