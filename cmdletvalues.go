package adpwsh

import "github.com/nemethhh/go-adcore"

// These were methods on types that now live in go-adcore. Go forbids defining
// a method on another package's type, and the values they produce are
// ActiveDirectory-module parameter vocabulary that has no business in a
// shared, backend-neutral module. They are functions here instead.

// cmdletScope maps a scope onto -SearchScope's accepted values. An empty scope
// defaults to subtree.
func cmdletScope(s adcore.SearchScope) (string, bool) {
	switch s {
	case "", adcore.SearchScopeSubtree:
		return "Subtree", true
	case adcore.SearchScopeBase:
		return "Base", true
	case adcore.SearchScopeOneLevel:
		return "OneLevel", true
	default:
		return "", false
	}
}

// cmdletGroupScope maps a scope onto the -GroupScope parameter's accepted
// values.
func cmdletGroupScope(s adcore.GroupScope) (string, bool) {
	switch s {
	case adcore.GroupScopeGlobal:
		return "Global", true
	case adcore.GroupScopeDomainLocal:
		return "DomainLocal", true
	case adcore.GroupScopeUniversal:
		return "Universal", true
	default:
		return "", false
	}
}

func cmdletGroupCategory(c adcore.GroupCategory) (string, bool) {
	switch c {
	case adcore.GroupCategorySecurity:
		return "Security", true
	case adcore.GroupCategoryDistribution:
		return "Distribution", true
	default:
		return "", false
	}
}

// cmdletInheritance maps onto the ActiveDirectorySecurityInheritance enum
// name. "Descendents" is not a typo here: .NET spells it that way, and
// correcting it produces a value the cmdlet rejects.
func cmdletInheritance(i adcore.Inheritance) (string, bool) {
	switch i {
	case adcore.InheritanceThis:
		return "None", true
	case adcore.InheritanceDescendants:
		return "Descendents", true
	case adcore.InheritanceChildren:
		return "Children", true
	default:
		return "", false
	}
}

// queryPayload builds the op payload for a search. It requests SizeLimit+1
// rows so the caller can distinguish "exactly at the limit" from "more exist"
// and error instead of silently truncating.
func queryPayload(q adcore.Query, project []string) map[string]any {
	filter := q.Filter
	if filter == "" {
		filter = "(objectClass=*)"
	}
	scope, _ := cmdletScope(q.Scope)
	return map[string]any{
		"filter":     filter,
		"searchBase": q.SearchBase,
		"scope":      scope,
		"sizeLimit":  q.SizeLimit + 1,
		"project":    project,
	}
}
