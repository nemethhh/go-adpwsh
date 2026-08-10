package adscript

import (
	"fmt"
	"sort"
	"strings"
)

// ConflictError reports an attribute named in more than one Set-AD* operation.
// The root package converts it into an *adpwsh.Error with KindConstraint; this
// package stays free of dependencies so it cannot form an import cycle.
type ConflictError struct {
	Attribute string
	Ops       []string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("adscript: attribute %q appears in more than one operation (%s)",
		e.Attribute, strings.Join(e.Ops, ", "))
}

// AttrOps accumulates the four attribute operations a single Set-AD* call can
// carry. Multi-valued attributes diff as sets and emit Add/Remove; Replace is
// reserved for single-valued attributes, because a wholesale replace of a
// multi-valued attribute is a lost update waiting to happen.
type AttrOps struct {
	add     map[string][]any
	remove  map[string][]any
	replace map[string]any
	clear   []string
}

func (o *AttrOps) AddValues(name string, values ...any) {
	if o.add == nil {
		o.add = map[string][]any{}
	}
	o.add[name] = append(o.add[name], values...)
}

func (o *AttrOps) RemoveValues(name string, values ...any) {
	if o.remove == nil {
		o.remove = map[string][]any{}
	}
	o.remove[name] = append(o.remove[name], values...)
}

func (o *AttrOps) ReplaceValue(name string, value any) {
	if o.replace == nil {
		o.replace = map[string]any{}
	}
	o.replace[name] = value
}

// ClearName marks an attribute for -Clear. AD has no empty-string attribute
// value, so both a null and an empty string clear; never -Replace with "".
func (o *AttrOps) ClearName(name string) { o.clear = append(o.clear, name) }

// IsEmpty reports whether there is anything to write.
func (o *AttrOps) IsEmpty() bool {
	return len(o.add) == 0 && len(o.remove) == 0 && len(o.replace) == 0 && len(o.clear) == 0
}

// isSetDiff reports whether ops (already sorted) is exactly the Add/Remove
// pair. That pair is the one legal collision: a multi-valued attribute diffed
// as a set names the same attribute in both, and AD's execution order —
// -Remove before -Add — makes the outcome deterministic rather than ambiguous.
// Every other pairing is a contradiction: -Replace wipes what -Add just wrote,
// and -Clear wipes whatever preceded it.
func isSetDiff(ops []string) bool {
	return len(ops) == 2 && ops[0] == "Add" && ops[1] == "Remove"
}

// Apply writes the non-empty operations into a cmdlet splat map. It returns a
// *ConflictError if any attribute name — compared case-insensitively, as LDAP
// names are — appears in more than one operation, except for the Add/Remove
// pair that expresses a multi-valued set diff.
func (o *AttrOps) Apply(splat map[string]any) error {
	seen := map[string][]string{}
	note := func(name, op string) {
		k := strings.ToLower(name)
		seen[k] = append(seen[k], op)
	}
	for n := range o.add {
		note(n, "Add")
	}
	for n := range o.remove {
		note(n, "Remove")
	}
	for n := range o.replace {
		note(n, "Replace")
	}
	for _, n := range o.clear {
		note(n, "Clear")
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if len(seen[n]) > 1 {
			sort.Strings(seen[n])
			if isSetDiff(seen[n]) {
				continue
			}
			return &ConflictError{Attribute: n, Ops: seen[n]}
		}
	}

	if len(o.add) > 0 {
		splat["Add"] = o.add
	}
	if len(o.remove) > 0 {
		splat["Remove"] = o.remove
	}
	if len(o.replace) > 0 {
		splat["Replace"] = o.replace
	}
	if len(o.clear) > 0 {
		c := append([]string(nil), o.clear...)
		sort.Strings(c)
		splat["Clear"] = c
	}
	return nil
}
