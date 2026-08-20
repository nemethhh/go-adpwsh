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

// ProtectedFromAccidentalDeletion puts an explicit Deny for Delete on the OU
// itself, and a move is authorised through that same right, so a protected OU
// cannot be moved until the flag is lifted. Renaming is unaffected, which is
// why only the move carries this.
//
// Verified against a real domain rather than reasoned about: with the flag set,
// Move-ADObject is refused with "Access is denied" and Rename-ADObject succeeds;
// once lifted, the move succeeds. The fake models protection as a stored
// boolean with no ACL semantics, which is why this went unnoticed until the
// acceptance suite ran.
func TestOUUpdateLiftsProtectionAroundAMove(t *testing.T) {
	tests := []struct {
		name             string
		startProtected   bool
		spec             adpwsh.OUSpec
		wantMove         bool
		wantUnprotect    bool
		wantProtectKey   bool
		wantProtectValue bool
	}{
		{
			name:           "a protected OU is unprotected for the move and protected again after",
			startProtected: true,
			spec:           adpwsh.OUSpec{Name: "Staff", Container: "OU=HQ,DC=corp,DC=local"},
			wantMove:       true, wantUnprotect: true, wantProtectKey: true, wantProtectValue: true,
		},
		{
			name:           "a rename alone needs no unprotecting",
			startProtected: true,
			spec:           adpwsh.OUSpec{Name: "People", Container: "DC=corp,DC=local"},
			wantMove:       false, wantUnprotect: false, wantProtectKey: false,
		},
		{
			// The caller wants it unprotected anyway, so it is left that way
			// rather than re-protected and immediately unprotected again.
			name:           "a move that also turns protection off does not restore it",
			startProtected: true,
			spec:           adpwsh.OUSpec{Name: "Staff", Container: "OU=HQ,DC=corp,DC=local", Protected: adpwsh.Bool(false)},
			wantMove:       true, wantUnprotect: true, wantProtectKey: false,
		},
		{
			// The ordering case: protection must be applied after the move. Set
			// first and the move it precedes is denied by the flag just written.
			name:           "a move that turns protection on applies it after the move",
			startProtected: false,
			spec:           adpwsh.OUSpec{Name: "Staff", Container: "OU=HQ,DC=corp,DC=local", Protected: adpwsh.Bool(true)},
			wantMove:       true, wantUnprotect: false, wantProtectKey: true, wantProtectValue: true,
		},
		{
			name:           "an unprotected OU moves with no protection traffic at all",
			startProtected: false,
			spec:           adpwsh.OUSpec{Name: "Staff", Container: "OU=HQ,DC=corp,DC=local"},
			wantMove:       true, wantUnprotect: false, wantProtectKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload map[string]any
			cur := ouAt("Staff", "DC=corp,DC=local")
			cur["protected"] = tt.startProtected
			tr := fake.New(func(c fake.Call) fake.Response {
				switch c.Op {
				case "rootdse":
					return fake.OK(rootDSE())
				case "ou_read":
					return fake.OK(cur)
				case "ou_update":
					payload = c.Payload
					return fake.OK(cur)
				}
				t.Fatalf("unexpected op %q", c.Op)
				return fake.Response{}
			})
			client := mustClient(t, adpwsh.Config{Transport: tr})

			if _, err := client.OU.Update(context.Background(), adpwsh.ByGUID("9f2c"), tt.spec); err != nil {
				t.Fatalf("Update: %v", err)
			}

			if got := payload["move"] != nil; got != tt.wantMove {
				t.Errorf("move present = %v, want %v (payload %v)", got, tt.wantMove, payload)
			}
			if got := payload["unprotectBeforeMove"] != nil; got != tt.wantUnprotect {
				t.Errorf("unprotectBeforeMove present = %v, want %v", got, tt.wantUnprotect)
			}
			protect, ok := payload["protect"]
			if ok != tt.wantProtectKey {
				t.Fatalf("protect present = %v, want %v (payload %v)", ok, tt.wantProtectKey, payload)
			}
			if ok && protect != tt.wantProtectValue {
				t.Errorf("protect = %v, want %v", protect, tt.wantProtectValue)
			}
		})
	}
}
