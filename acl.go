package adpwsh

import (
	"sort"
	"strings"
)

// ACEType is an access-control entry's allow/deny sense.
type ACEType string

const (
	ACEAllow ACEType = "Allow"
	ACEDeny  ACEType = "Deny"
)

// Right is one System.DirectoryServices.ActiveDirectoryRights value, by name.
type Right string

// Inheritance is how an ACE propagates. It maps onto
// System.DirectoryServices.ActiveDirectorySecurityInheritance.
type Inheritance string

const (
	InheritanceThis        Inheritance = "this"        // this object only
	InheritanceDescendants Inheritance = "descendants" // all descendants, scoped by InheritedObjectType
	InheritanceChildren    Inheritance = "children"    // immediate children only
)

// cmdletValue maps onto the ActiveDirectorySecurityInheritance enum name.
func (i Inheritance) cmdletValue() (string, bool) {
	switch i {
	case InheritanceThis:
		return "None", true
	case InheritanceDescendants:
		return "Descendents", true // note: .NET spells it "Descendents"
	case InheritanceChildren:
		return "Children", true
	default:
		return "", false
	}
}

// ACE is one explicit access-control entry as the library reads and writes it.
// Object types are GUIDs at this layer (already resolved from friendly names).
type ACE struct {
	Trustee             string // SID
	Type                ACEType
	Rights              []Right
	ObjectType          string // GUID; "" = all
	InheritedObjectType string // GUID; "" = all child classes
	Inheritance         Inheritance
	Inherited           bool // read-only: system-stamped copy; never managed
}

// ACESpec is the friendly, unresolved form a delegation template emits and the
// provider maps to config. ObjectType and ObjectClass are friendly names or GUIDs.
type ACESpec struct {
	Rights      []Right
	ObjectType  string
	Scope       Inheritance
	ObjectClass string
	Type        ACEType
}

// SchemaRefKind is which schema partition a name is resolved against.
type SchemaRefKind string

const (
	RefAttribute     SchemaRefKind = "attribute"
	RefClass         SchemaRefKind = "class"
	RefExtendedRight SchemaRefKind = "extended_right"
)

// SchemaRef is a friendly name to resolve to a GUID.
type SchemaRef struct {
	Kind SchemaRefKind
	Name string
}

// DelegationTask names a curated bundle of ACEs.
type DelegationTask string

const (
	TaskResetUserPasswords    DelegationTask = "reset_user_passwords"
	TaskManageUsers           DelegationTask = "manage_users"
	TaskModifyGroupMembership DelegationTask = "modify_group_membership"
	TaskManageGroups          DelegationTask = "manage_groups"
)

// canonicalACEKey is the semantic identity of an ACE: case-insensitive, and
// order-insensitive over Rights, so two representations of the same grant match.
// It is what drift detection and revoke-by-identity compare on.
func canonicalACEKey(a ACE) string {
	rights := make([]string, len(a.Rights))
	for i, r := range a.Rights {
		rights[i] = strings.ToLower(string(r))
	}
	sort.Strings(rights)
	parts := []string{
		strings.ToLower(a.Trustee),
		strings.ToLower(string(a.Type)),
		strings.Join(rights, "+"),
		strings.ToLower(a.ObjectType),
		strings.ToLower(a.InheritedObjectType),
		strings.ToLower(string(a.Inheritance)),
	}
	return strings.Join(parts, "|")
}
