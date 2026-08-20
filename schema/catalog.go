// Package schema holds the Active Directory schema catalog: every attribute's
// type and constraints, and every exported class's effective set of allowed
// attributes. It is data and a reader, nothing else. The exporter that produces
// a catalog is build-time tooling in cmd/adschema, and no code in this package
// reaches a directory.
package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
)

// Catalog is one export of one forest's schema.
type Catalog struct {
	Source     Source               `json:"source"`
	Attributes map[string]Attribute `json:"attributes"`
	Classes    map[string]Class     `json:"classes"`
}

// Source is provenance. A stale or foreign catalog must be identifiable
// without diffing it against a fresh export, so where it came from travels
// with it.
type Source struct {
	Domain        string `json:"domain"`
	ForestMode    string `json:"forestMode"`
	SchemaNC      string `json:"schemaNC"`
	ObjectVersion int    `json:"objectVersion"`
	ExportedAt    string `json:"exportedAt"`
	Exporter      string `json:"exporter"`
}

// Attribute is one attributeSchema object, reduced to what a consumer needs in
// order to decide whether a value is legal.
//
// Syntax is recorded raw. Deciding that 2.5.5.12 becomes a string and 2.5.5.16
// a number belongs to whichever feature consumes the catalog, where the
// trade-offs are visible. RangeLower and RangeUpper are absent where the schema
// states no bound; nil and absent mean the same thing. SystemOnly attributes
// are retained rather than filtered: a consumer that wants to reject writes to
// them needs to know they exist, and a consumer that only reads may
// legitimately want them.
type Attribute struct {
	OID          string `json:"oid"`
	Syntax       string `json:"syntax"`
	OMSyntax     int    `json:"omSyntax"`
	SingleValued bool   `json:"singleValued"`
	SystemOnly   bool   `json:"systemOnly"`
	RangeLower   *int   `json:"rangeLower,omitempty"`
	RangeUpper   *int   `json:"rangeUpper,omitempty"`
	Indexed      bool   `json:"indexed"`
	LinkID       *int   `json:"linkId"`
}

// Class is one classSchema object's *effective* attribute set: the union,
// across the whole inheritance closure, of mayContain, systemMayContain,
// mustContain and systemMustContain.
//
// Via records which class in the closure contributed each attribute. It is the
// diagnostic that makes the closure reviewable: when an operator asks why some
// attribute is or is not allowed on a class, the answer is in the file.
type Class struct {
	Structural bool              `json:"structural"`
	Mandatory  []string          `json:"mandatory"`
	Optional   []string          `json:"optional"`
	Via        map[string]string `json:"via"`
}

// Load decodes a catalog and validates it. Unknown fields are tolerated: a
// catalog is a data format, and an older reader should still read a newer file.
func Load(r io.Reader) (*Catalog, error) {
	var c Catalog
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return nil, fmt.Errorf("schema: cannot decode the catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadFile reads a catalog from a path.
func LoadFile(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("schema: cannot open the catalog: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// ClassNames returns the exported class names, sorted.
func (c *Catalog) ClassNames() []string { return slices.Sorted(maps.Keys(c.Classes)) }

// Validate reports the integrity properties a consumer depends on: every
// attribute a class names exists in the attribute map, and every named
// attribute has exactly one via entry. Both directions are checked, because a
// via entry naming nothing is as much a bug as a missing one.
func (c *Catalog) Validate() error {
	var problems []string
	for _, name := range c.ClassNames() {
		cl := c.Classes[name]
		named := make(map[string]bool, len(cl.Mandatory)+len(cl.Optional))
		for _, group := range [][]string{cl.Mandatory, cl.Optional} {
			for _, attr := range group {
				named[attr] = true
				if _, ok := c.Attributes[attr]; !ok {
					problems = append(problems, fmt.Sprintf(
						"class %s names attribute %s, which the catalog does not carry", name, attr))
				}
				if cl.Via[attr] == "" {
					problems = append(problems, fmt.Sprintf(
						"class %s names attribute %s with no via entry", name, attr))
				}
			}
		}
		for _, attr := range slices.Sorted(maps.Keys(cl.Via)) {
			if !named[attr] {
				problems = append(problems, fmt.Sprintf(
					"class %s has a via entry for %s, which it does not name", name, attr))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	shown := problems
	if len(shown) > 10 {
		shown = shown[:10]
	}
	return fmt.Errorf("schema: the catalog is inconsistent (%d problem(s), showing %d):\n  %s",
		len(problems), len(shown), strings.Join(shown, "\n  "))
}
