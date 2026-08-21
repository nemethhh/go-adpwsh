package fake

import (
	"fmt"
	"strings"
)

// matchFilter evaluates a bounded subset of RFC 4515 against one object: the
// operators & | !, equality, presence (attr=*), and leading/trailing/contains
// substring (attr=a*b*c). It is deliberately not a full engine — the provider's
// filter_by path only emits equality, and raw ldap_filter beyond this grammar
// is validated only against the real domain. An unsupported construct is an
// error, never a silent mismatch.
func matchFilter(o *DirectoryObject, filter string) (bool, error) {
	f := strings.TrimSpace(filter)
	if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") {
		return false, fmt.Errorf("fake: malformed filter %q", filter)
	}
	inner := f[1 : len(f)-1]
	switch {
	case strings.HasPrefix(inner, "&"), strings.HasPrefix(inner, "|"):
		op := inner[0]
		parts, err := splitFilters(inner[1:])
		if err != nil {
			return false, err
		}
		for _, p := range parts {
			m, err := matchFilter(o, p)
			if err != nil {
				return false, err
			}
			if op == '&' && !m {
				return false, nil
			}
			if op == '|' && m {
				return true, nil
			}
		}
		return op == '&', nil
	case strings.HasPrefix(inner, "!"):
		m, err := matchFilter(o, inner[1:])
		if err != nil {
			return false, err
		}
		return !m, nil
	default:
		return matchItem(o, inner)
	}
}

// splitFilters divides a run of parenthesised sub-filters "(a)(b)(c)" at the
// top level, honouring nesting.
func splitFilters(s string) ([]string, error) {
	var parts []string
	depth, start := 0, -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				parts = append(parts, s[start:i+1])
			}
			if depth < 0 {
				return nil, fmt.Errorf("fake: unbalanced filter %q", s)
			}
		}
	}
	if depth != 0 || len(parts) == 0 {
		return nil, fmt.Errorf("fake: unbalanced filter %q", s)
	}
	return parts, nil
}

// matchItem evaluates a single "attr=value" assertion. Only '=' is supported;
// ~=, >=, <= and extensible matches error.
func matchItem(o *DirectoryObject, item string) (bool, error) {
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return false, fmt.Errorf("fake: unsupported assertion %q", item)
	}
	if c := item[eq-1]; c == '~' || c == '>' || c == '<' || c == ':' {
		return false, fmt.Errorf("fake: unsupported operator in %q", item)
	}
	attr := item[:eq]
	pattern := unescapeFilterValue(item[eq+1:])
	value, present := fakeAttr(o, attr)
	if pattern == "*" {
		return present, nil
	}
	if !present {
		return false, nil
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(value, pattern), nil
	}
	return matchWildcard(value, pattern), nil
}

// matchWildcard matches a value against a pattern whose '*' are wildcards,
// case-insensitively. Splitting on '*' yields the required ordered substrings.
func matchWildcard(value, pattern string) bool {
	value = strings.ToLower(value)
	segs := strings.Split(strings.ToLower(pattern), "*")
	pos := 0
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		idx := strings.Index(value[pos:], seg)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // no leading '*': must anchor at the start
		}
		pos += idx + len(seg)
	}
	if last := segs[len(segs)-1]; last != "" {
		return strings.HasSuffix(value, last) // no trailing '*': anchor at the end
	}
	return true
}

// fakeAttr resolves an LDAP attribute name to the object's stored value,
// case-insensitively, with the small alias set the provider's tests exercise.
// An attribute the fake does not store is reported absent.
func fakeAttr(o *DirectoryObject, ldapName string) (string, bool) {
	switch strings.ToLower(ldapName) {
	case "distinguishedname", "dn":
		return o.DN, true
	case "objectclass":
		return o.Class, true
	case "cn", "name":
		return asString(o.Data["name"]), o.Data["name"] != nil
	case "samaccountname":
		v, ok := o.Data["samAccountName"]
		return asString(v), ok && asString(v) != ""
	default:
		v, ok := o.Data[strings.ToLower(ldapName)]
		if !ok {
			// second chance: exact stored key (Data keys are camelCase)
			for k, val := range o.Data {
				if strings.EqualFold(k, ldapName) {
					return asString(val), asString(val) != ""
				}
			}
			return "", false
		}
		return asString(v), asString(v) != ""
	}
}

// unescapeFilterValue reverses RFC 4515 \XX hex escaping.
func unescapeFilterValue(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 <= len(s)-1 {
			hi, lo := fromHex(s[i+1]), fromHex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}
