package adpwsh

// SearchScope is the -SearchScope argument to a directory search.
type SearchScope string

const (
	SearchScopeBase     SearchScope = "base"
	SearchScopeOneLevel SearchScope = "onelevel"
	SearchScopeSubtree  SearchScope = "subtree"
)

// cmdletValue maps a scope onto -SearchScope's accepted values, like
// GroupScope.cmdletValue. An empty scope defaults to subtree.
func (s SearchScope) cmdletValue() (string, bool) {
	switch s {
	case "", SearchScopeSubtree:
		return "Subtree", true
	case SearchScopeBase:
		return "Base", true
	case SearchScopeOneLevel:
		return "OneLevel", true
	default:
		return "", false
	}
}

// defaultSizeLimit caps a search unless the caller sets its own limit. Large
// enough for a realistic subtree, small enough that a domain-wide accident
// errors rather than dragging.
const defaultSizeLimit = 1000

// Query is a directory search. The zero value searches the whole domain subtree
// for every object of the sub-client's class, capped at the default limit.
type Query struct {
	Filter     string      // a COMPLETE LDAP filter; "" ⇒ "(objectClass=*)"
	SearchBase string      // DN; "" ⇒ the pinned domain's defaultNamingContext
	Scope      SearchScope // "" ⇒ subtree
	SizeLimit  int         // ≤ 0 ⇒ defaultSizeLimit
}

// withDefaults resolves the zero-value fields against the pinned domain.
func (q Query) withDefaults(dnc string) Query {
	if q.SearchBase == "" {
		q.SearchBase = dnc
	}
	if q.Scope == "" {
		q.Scope = SearchScopeSubtree
	}
	if q.SizeLimit <= 0 {
		q.SizeLimit = defaultSizeLimit
	}
	return q
}

// payload builds the op payload. It requests SizeLimit+1 rows so the caller can
// distinguish "exactly at the limit" from "more exist" and error instead of
// silently truncating.
func (q Query) payload(project []string) map[string]any {
	filter := q.Filter
	if filter == "" {
		filter = "(objectClass=*)"
	}
	scope, _ := q.Scope.cmdletValue()
	return map[string]any{
		"filter":     filter,
		"searchBase": q.SearchBase,
		"scope":      scope,
		"sizeLimit":  q.SizeLimit + 1,
		"project":    project,
	}
}
