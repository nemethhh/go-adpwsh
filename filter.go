package adpwsh

import "github.com/nemethhh/go-adpwsh/internal/addn"

// EscapeFilter escapes one LDAP assertion value per RFC 4515. Every value the
// provider puts inside a filter goes through here; hand-rolled quoting is the
// defect class this exists to retire.
func EscapeFilter(value string) string { return addn.EscapeFilter(value) }

// Equal builds an equality assertion "(attr=<escaped value>)". The attribute
// name is a caller-controlled schema identifier and is not escaped; only the
// value is.
func Equal(attr, value string) string {
	return "(" + attr + "=" + EscapeFilter(value) + ")"
}

// And composes a conjunction. Zero terms is the empty filter (the caller
// decides the default); one term is returned unwrapped; two or more are joined
// under a single "&".
func And(terms ...string) string {
	switch len(terms) {
	case 0:
		return ""
	case 1:
		return terms[0]
	default:
		out := "(&"
		for _, t := range terms {
			out += t
		}
		return out + ")"
	}
}
