package adpwsh

import (
	"context"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// SchemaClient resolves friendly schema names to GUIDs.
type SchemaClient struct{ c *core }

// wellKnown maps base-schema names to their forest-invariant GUIDs, so the
// common delegation vocabulary resolves with no directory round trip.
var wellKnown = map[SchemaRef]string{
	{Kind: RefExtendedRight, Name: "Reset Password"}: "00299570-246d-11d0-a768-00aa006e0529",
	{Kind: RefClass, Name: "user"}:                   "bf967aba-0de6-11d0-a285-00aa003049e2",
	{Kind: RefClass, Name: "group"}:                  "bf967a9c-0de6-11d0-a285-00aa003049e2",
	{Kind: RefAttribute, Name: "member"}:             "bf9679c0-0de6-11d0-a285-00aa003049e2",
	{Kind: RefAttribute, Name: "pwdLastSet"}:         "bf967a0a-0de6-11d0-a285-00aa003049e2",
}

func wellKnownGUID(ref SchemaRef) (string, bool) {
	g, ok := wellKnown[ref]
	return g, ok
}

// resolveFilter builds the RFC 4515-escaped LDAP filter for a ref. The value is
// escaped in Go and travels as a parameter, never as script text.
func resolveFilter(ref SchemaRef) string {
	name := addn.EscapeFilter(ref.Name)
	switch ref.Kind {
	case RefClass:
		return "(&(objectClass=classSchema)(lDAPDisplayName=" + name + "))"
	case RefExtendedRight:
		return "(&(objectClass=controlAccessRight)(displayName=" + name + "))"
	default: // RefAttribute
		return "(&(objectClass=attributeSchema)(lDAPDisplayName=" + name + "))"
	}
}

// Resolve returns a GUID for each ref. Well-known names are answered from the
// in-process table; the rest go to the directory in one round trip. A name that
// resolves to nothing is returned as an empty string (the caller decides whether
// that is an error).
func (s *SchemaClient) Resolve(ctx context.Context, refs []SchemaRef) (map[SchemaRef]string, error) {
	out := make(map[SchemaRef]string, len(refs))
	var miss []SchemaRef
	for _, ref := range refs {
		if g, ok := wellKnownGUID(ref); ok {
			out[ref] = g
			continue
		}
		miss = append(miss, ref)
	}
	if len(miss) == 0 {
		return out, nil
	}

	payloadRefs := make([]map[string]any, len(miss))
	for i, ref := range miss {
		payloadRefs[i] = map[string]any{
			"kind":   string(ref.Kind),
			"name":   ref.Name,
			"filter": resolveFilter(ref),
		}
	}
	var res struct {
		Resolved map[string]string `json:"resolved"`
	}
	if err := s.c.exec(ctx, adscript.OpSchemaResolve, map[string]any{"refs": payloadRefs}, &res); err != nil {
		return nil, err
	}
	for _, ref := range miss {
		out[ref] = res.Resolved[ref.Name]
	}
	return out, nil
}
