// Package adschema is the schema exporter's guts: one fetch over a transport,
// the inheritance closure that turns what was fetched into effective attribute
// sets, and the deterministic serialiser that writes the catalog.
//
// It is build-time tooling reached only from cmd/adschema. Nothing in an apply
// path queries the schema, which is why the export is not one of the library's
// operations.
package adschema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// exporterID is recorded in every catalog's provenance.
const exporterID = "adschema/1"

// fetchOp names this operation in errors and log lines. It is not an op in
// adscript's closed set, and deliberately reads as what it is.
const fetchOp = "Schema.Fetch"

// Credential is the identity the AD cmdlets run as.
//
// The library's own adpwsh.Credential carries a Secret whose plaintext only the
// library can read, so the exporter carries its own instead. That is safe here
// and nowhere else: this package never logs a payload, and the CLI takes the
// password from an environment variable rather than argv, where the process
// list would show it.
type Credential struct {
	Username string
	Password string
}

// FetchOptions is what a fetch needs beyond a transport.
type FetchOptions struct {
	// Server pins the domain controller every cmdlet targets. Empty lets the
	// Windows host resolve one; the export is a single execution, so one
	// consistent view is guaranteed either way.
	Server string

	// Credential, when set, becomes the -Credential passed to every cmdlet.
	Credential *Credential
}

// Raw is what one fetch returns: the schema as the directory states it, before
// any closure is resolved.
type Raw struct {
	Source     RawSource      `json:"source"`
	Attributes []RawAttribute `json:"attributes"`
	Classes    []RawClass     `json:"classes"`
}

// RawSource is the provenance the directory itself supplies.
type RawSource struct {
	Domain        string `json:"domain"`
	ForestMode    string `json:"forestMode"`
	SchemaNC      string `json:"schemaNC"`
	ObjectVersion int    `json:"objectVersion"`
}

// RawAttribute is one attributeSchema object, verbatim. searchFlags is kept raw
// here and reduced to the indexed bit in Build, so the reduction is one visible
// step rather than a decision buried in a script.
type RawAttribute struct {
	Name         string `json:"name"`
	OID          string `json:"oid"`
	Syntax       string `json:"syntax"`
	OMSyntax     int    `json:"omSyntax"`
	SingleValued bool   `json:"singleValued"`
	SystemOnly   bool   `json:"systemOnly"`
	RangeLower   *int   `json:"rangeLower"`
	RangeUpper   *int   `json:"rangeUpper"`
	SearchFlags  int    `json:"searchFlags"`
	LinkID       *int   `json:"linkId"`
}

// RawClass is one classSchema object, verbatim. Every name in it is an
// lDAPDisplayName: LDAP presents the OID-syntax attributes subClassOf,
// auxiliaryClass and mayContain as the referenced object's display name.
type RawClass struct {
	Name                 string   `json:"name"`
	Category             int      `json:"category"`
	SubClassOf           string   `json:"subClassOf"`
	AuxiliaryClass       []string `json:"auxiliaryClass"`
	SystemAuxiliaryClass []string `json:"systemAuxiliaryClass"`
	MayContain           []string `json:"mayContain"`
	SystemMayContain     []string `json:"systemMayContain"`
	MustContain          []string `json:"mustContain"`
	SystemMustContain    []string `json:"systemMustContain"`
}

// Fetch reads the whole schema in one script execution.
//
// One execution, not one per class: the schema holds hundreds of classes and
// thousands of attributes, and a query per class is hundreds of round trips
// each paying its own Import-Module ActiveDirectory. The closure is resolved
// afterwards, in Go, where it needs no directory.
func Fetch(ctx context.Context, tr adpwsh.Transport, opts FetchOptions) (*Raw, error) {
	script, err := adscript.ToolScript(adscript.ToolSchemaFetch)
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindUnknown, Op: fetchOp, Err: err}
	}

	payload := map[string]any{"op": adscript.ToolSchemaFetch}
	if opts.Server != "" {
		payload["server"] = opts.Server
	}
	if opts.Credential != nil {
		payload["credential"] = map[string]any{
			"username": opts.Credential.Username,
			"password": opts.Credential.Password,
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindUnknown, Op: fetchOp,
			Err: fmt.Errorf("cannot encode the payload: %w", err)}
	}

	res, runErr := tr.Run(ctx, adscript.EncodeCommand(script), body)
	if runErr != nil {
		var e *adpwsh.Error
		if errors.As(runErr, &e) {
			return nil, e
		}
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: fetchOp, Err: runErr}
	}
	data, err := adpwsh.ParseEnvelope(fetchOp, res)
	if err != nil {
		return nil, err
	}

	var raw Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: fetchOp,
			Err: fmt.Errorf("cannot decode the schema: %w", err)}
	}
	// A partial fetch is the failure a retry loop would paper over, so it is
	// fatal and says what it saw.
	if len(raw.Attributes) == 0 || len(raw.Classes) == 0 {
		return nil, &adpwsh.Error{Kind: adpwsh.KindSchema, Op: fetchOp,
			Err: fmt.Errorf("the fetch returned %d attributes and %d classes; a schema has thousands of the first and hundreds of the second",
				len(raw.Attributes), len(raw.Classes))}
	}
	return &raw, nil
}
