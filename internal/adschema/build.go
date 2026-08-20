package adschema

import (
	"fmt"
	"time"

	"github.com/nemethhh/go-adpwsh/schema"
)

// searchFlagIndexed is searchFlags bit 0 — fATTINDEX. The catalog records the
// bit rather than the whole word because that is the part a consumer acts on,
// and the rest of searchFlags describes indexing strategy, not legality.
const searchFlagIndexed = 1

// Build assembles a catalog from one fetch.
//
// exportedAt is a parameter, not a clock read, and nothing below main reads a
// clock: emit must be a pure function of its input, or regenerating an
// unchanged schema would not be byte-identical and make schema-check could not
// tell a real schema change from a fresh timestamp.
//
// Every attribute in the schema is carried, not only those the exported classes
// reach. The goal is a catalog of the schema; --classes decides which classes
// get an effective set resolved, and nothing more.
func Build(raw *Raw, classNames []string, exportedAt time.Time) (*schema.Catalog, error) {
	classes, err := Resolve(raw, classNames)
	if err != nil {
		return nil, err
	}

	attributes := make(map[string]schema.Attribute, len(raw.Attributes))
	for _, a := range raw.Attributes {
		if a.Name == "" {
			return nil, fmt.Errorf("the fetch returned an attribute with no lDAPDisplayName (oid %q): the fetch was partial", a.OID)
		}
		attributes[a.Name] = schema.Attribute{
			OID:          a.OID,
			Syntax:       a.Syntax,
			OMSyntax:     a.OMSyntax,
			SingleValued: a.SingleValued,
			SystemOnly:   a.SystemOnly,
			RangeLower:   a.RangeLower,
			RangeUpper:   a.RangeUpper,
			Indexed:      a.SearchFlags&searchFlagIndexed != 0,
			LinkID:       a.LinkID,
		}
	}

	cat := &schema.Catalog{
		Source: schema.Source{
			Domain:        raw.Source.Domain,
			ForestMode:    raw.Source.ForestMode,
			SchemaNC:      raw.Source.SchemaNC,
			ObjectVersion: raw.Source.ObjectVersion,
			// RFC3339 carries no fractional seconds, so a caller's nanoseconds
			// cannot reach the file.
			ExportedAt: exportedAt.UTC().Format(time.RFC3339),
			Exporter:   exporterID,
		},
		Attributes: attributes,
		Classes:    classes,
	}
	// Never emit a catalog this module's own reader would reject.
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}
