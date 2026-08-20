package adschema

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/nemethhh/go-adpwsh/schema"
)

// objectClassCategory values, from the schema itself: 0 is an 88-class, 1
// structural, 2 abstract, 3 auxiliary.
const categoryStructural = 1

// Resolve computes each named class's effective attribute set: the union,
// across the whole inheritance closure, of mayContain, systemMayContain,
// mustContain and systemMustContain. The closure follows subClassOf and, at
// every step, auxiliaryClass and systemAuxiliaryClass — transitively, because
// an auxiliary class is itself a class with its own parents.
//
// This is why the exporter is not a dump. Reading mayContain off the class
// itself misses 129 attributes on organizationalUnit, 167 on group and 247 on
// user against a stock Windows Server 2025 schema, and it misses them in the
// direction that matters: a validator built on it rejects attributes Active
// Directory accepts.
func Resolve(raw *Raw, classNames []string) (map[string]schema.Class, error) {
	ix := newIndex(raw)
	out := make(map[string]schema.Class, len(classNames))
	for _, want := range classNames {
		cl, ok := ix.classes[fold(want)]
		if !ok {
			return nil, fmt.Errorf("no class named %q exists in this schema", want)
		}
		contrib, err := ix.closure(cl)
		if err != nil {
			return nil, fmt.Errorf("resolving class %s: %w", cl.Name, err)
		}

		mandatory, optional := []string{}, []string{}
		via := make(map[string]string, len(contrib))
		for _, attr := range slices.Sorted(maps.Keys(contrib)) {
			c := contrib[attr]
			if c.mandatory {
				mandatory = append(mandatory, attr)
			} else {
				optional = append(optional, attr)
			}
			via[attr] = c.class
		}
		sort.Strings(mandatory)
		sort.Strings(optional)

		// Keyed by the schema's own name, so --classes USER emits "user".
		out[cl.Name] = schema.Class{
			Structural: cl.Category == categoryStructural,
			Mandatory:  mandatory,
			Optional:   optional,
			Via:        via,
		}
	}
	return out, nil
}

// AllStructural returns every structural class's name, sorted. --classes all is
// what an untyped resource would eventually need, and it costs nothing once the
// closure exists.
func AllStructural(raw *Raw) []string {
	out := make([]string, 0, len(raw.Classes))
	for i := range raw.Classes {
		if raw.Classes[i].Category == categoryStructural {
			out = append(out, raw.Classes[i].Name)
		}
	}
	sort.Strings(out)
	return out
}

// index makes the fetched slices addressable by folded name. LDAP names are
// case-insensitive, and nothing guarantees that a mayContain value matches the
// attribute's own lDAPDisplayName byte for byte, so every lookup folds and
// every emitted name is the canonical one.
type index struct {
	classes map[string]*RawClass
	attrs   map[string]string // folded name -> canonical name
}

func newIndex(raw *Raw) *index {
	ix := &index{
		classes: make(map[string]*RawClass, len(raw.Classes)),
		attrs:   make(map[string]string, len(raw.Attributes)),
	}
	for i := range raw.Classes {
		ix.classes[fold(raw.Classes[i].Name)] = &raw.Classes[i]
	}
	for i := range raw.Attributes {
		ix.attrs[fold(raw.Attributes[i].Name)] = raw.Attributes[i].Name
	}
	return ix
}

func fold(s string) string { return strings.ToLower(s) }

// contribution is one attribute's provenance within one closure.
type contribution struct {
	depth     int
	class     string
	mandatory bool
}

type queued struct {
	class *RawClass
	depth int
}

// closure walks one class's inheritance closure breadth-first and returns every
// attribute it reaches.
//
// The visited-set is what terminates the walk: top is its own subClassOf, so
// "stop at the root" never fires. Deduplicating by class rather than by
// attribute is what keeps the walk linear — diamonds are normal, since several
// auxiliary classes are reachable by more than one path, and a walk that
// deduplicated only attributes would re-walk them exponentially.
func (ix *index) closure(start *RawClass) (map[string]*contribution, error) {
	contrib := map[string]*contribution{}
	visited := map[string]bool{fold(start.Name): true}
	queue := []queued{{class: start, depth: 0}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		cl := cur.class

		for _, group := range []struct {
			names     []string
			mandatory bool
		}{
			{cl.MustContain, true},
			{cl.SystemMustContain, true},
			{cl.MayContain, false},
			{cl.SystemMayContain, false},
		} {
			for _, name := range group.names {
				canonical, ok := ix.attrs[fold(name)]
				if !ok {
					return nil, fmt.Errorf(
						"class %s names attribute %q, which the fetch did not return: the fetch was partial",
						cl.Name, name)
				}
				record(contrib, canonical, cur.depth, cl.Name, group.mandatory)
			}
		}

		// A fresh slice: appending to cl.AuxiliaryClass would write through its
		// backing array and corrupt the fetched data.
		next := make([]string, 0, 1+len(cl.AuxiliaryClass)+len(cl.SystemAuxiliaryClass))
		next = append(next, cl.SubClassOf)
		next = append(next, cl.AuxiliaryClass...)
		next = append(next, cl.SystemAuxiliaryClass...)

		for _, name := range next {
			if name == "" {
				continue
			}
			f := fold(name)
			if visited[f] {
				continue
			}
			parent, ok := ix.classes[f]
			if !ok {
				return nil, fmt.Errorf(
					"class %s refers to class %q, which the fetch did not return: the fetch was partial",
					cl.Name, name)
			}
			visited[f] = true
			queue = append(queue, queued{class: parent, depth: cur.depth + 1})
		}
	}
	return contrib, nil
}

// record applies the two rules that make the output reproducible.
//
// The contributor kept is the one nearest the exported class, measured in steps
// through the closure, with ties broken by name ascending. The rule exists so
// the output is reproducible, not because the nearest contributor is more
// truthful than another.
//
// Mandatory wins wherever both occur: a class cannot relax a must-contain it
// inherits, so an attribute contributed as mustContain anywhere in the closure
// is mandatory even if another class lists it as mayContain.
func record(into map[string]*contribution, attr string, depth int, class string, mandatory bool) {
	c, ok := into[attr]
	if !ok {
		into[attr] = &contribution{depth: depth, class: class, mandatory: mandatory}
		return
	}
	if mandatory {
		c.mandatory = true
	}
	if depth < c.depth || (depth == c.depth && class < c.class) {
		c.depth, c.class = depth, class
	}
}
