package adpwsh

import (
	"context"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// ACLClient reads and writes the discretionary ACL of a directory object. It is
// never authoritative over the whole DACL: Grant adds explicit ACEs and Revoke
// removes exactly the ACEs named, leaving inherited entries and other trustees
// untouched.
type ACLClient struct{ c *core }

type aceJSON struct {
	Trustee             string   `json:"trustee"`
	Type                string   `json:"type"`
	Rights              []string `json:"rights"`
	ObjectType          string   `json:"objectType"`
	InheritedObjectType string   `json:"inheritedObjectType"`
	Inheritance         string   `json:"inheritance"`
	Inherited           bool     `json:"inherited"`
}

func (j aceJSON) model() ACE {
	rights := make([]Right, len(j.Rights))
	for i, r := range j.Rights {
		rights[i] = Right(r)
	}
	return ACE{
		Trustee: j.Trustee, Type: ACEType(j.Type), Rights: rights,
		ObjectType: normalizeGUID(j.ObjectType), InheritedObjectType: normalizeGUID(j.InheritedObjectType),
		Inheritance: inheritanceFromCmdlet(j.Inheritance), Inherited: j.Inherited,
	}
}

// normalizeGUID turns the all-zero GUID the directory reports for "all" into the
// empty string the library uses for it.
func normalizeGUID(g string) string {
	if g == "00000000-0000-0000-0000-000000000000" {
		return ""
	}
	return g
}

// inheritanceFromCmdlet is the inverse of Inheritance.cmdletValue.
func inheritanceFromCmdlet(v string) Inheritance {
	switch v {
	case "None":
		return InheritanceThis
	case "Descendents", "All":
		return InheritanceDescendants
	case "Children", "SelfAndChildren":
		return InheritanceChildren
	default:
		return Inheritance(v)
	}
}

// aceToPayload renders ACEs as the JSON the grant/revoke ops consume. The
// inheritance is mapped to its .NET enum name here; an invalid one is sent
// verbatim and the DC rejects it (fail-closed).
func aceToPayload(aces []ACE) []map[string]any {
	out := make([]map[string]any, len(aces))
	for i, a := range aces {
		inh, _ := a.Inheritance.cmdletValue()
		rights := make([]string, len(a.Rights))
		for j, r := range a.Rights {
			rights[j] = string(r)
		}
		out[i] = map[string]any{
			"trustee":             a.Trustee,
			"type":                string(a.Type),
			"rights":              rights,
			"objectType":          a.ObjectType,
			"inheritedObjectType": a.InheritedObjectType,
			"inheritance":         inh,
		}
	}
	return out
}

// Get returns every ACE on target's DACL, including inherited ones (the
// Inherited flag distinguishes them). The caller matches the explicit ACE it
// owns and ignores the rest.
func (a *ACLClient) Get(ctx context.Context, target Identity) ([]ACE, error) {
	const op = "ACL.Get"
	var out struct {
		ACEs []aceJSON `json:"aces"`
	}
	if err := a.c.exec(ctx, adscript.OpACLRead, map[string]any{"target": target.identityArg()}, &out); err != nil {
		return nil, withIdentity(err, op, target)
	}
	aces := make([]ACE, len(out.ACEs))
	for i, j := range out.ACEs {
		aces[i] = j.model()
	}
	return aces, nil
}

// Grant adds each ACE to target's DACL. Adding an ACE that is already present is
// a no-op on the DC, so Grant is idempotent.
func (a *ACLClient) Grant(ctx context.Context, target Identity, aces []ACE) error {
	const op = "ACL.Grant"
	if len(aces) == 0 {
		return nil
	}
	unlock := a.c.locks.lock(target.identityArg())
	defer unlock()
	var out struct {
		GUID string `json:"guid"`
	}
	if err := a.c.exec(ctx, adscript.OpACLGrant, map[string]any{
		"target": target.identityArg(), "aces": aceToPayload(aces),
	}, &out); err != nil {
		return withIdentity(err, op, target)
	}
	return a.c.replicate(ctx, out.GUID)
}

// Revoke removes exactly the ACEs named from target's DACL. Removing an ACE that
// is absent is a no-op, so Revoke is idempotent.
func (a *ACLClient) Revoke(ctx context.Context, target Identity, aces []ACE) error {
	const op = "ACL.Revoke"
	if len(aces) == 0 {
		return nil
	}
	unlock := a.c.locks.lock(target.identityArg())
	defer unlock()
	var out struct {
		GUID string `json:"guid"`
	}
	if err := a.c.exec(ctx, adscript.OpACLRevoke, map[string]any{
		"target": target.identityArg(), "aces": aceToPayload(aces),
	}, &out); err != nil {
		return withIdentity(err, op, target)
	}
	return a.c.replicate(ctx, out.GUID)
}
