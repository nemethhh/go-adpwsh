package adschema

import (
	"encoding/json"
	"fmt"

	"github.com/nemethhh/go-adpwsh/schema"
)

// Emit serialises a catalog deterministically: object keys sorted, which
// encoding/json does for maps; arrays sorted, which Resolve does; two-space
// indentation; exactly one trailing newline.
//
// Regenerating an unchanged schema must produce a byte-identical file. That is
// what makes a real schema change legible as a diff, and what lets
// make schema-check prove the committed catalog matches the domain.
func Emit(cat *schema.Catalog) ([]byte, error) {
	body, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot serialise the catalog: %w", err)
	}
	return append(body, '\n'), nil
}
