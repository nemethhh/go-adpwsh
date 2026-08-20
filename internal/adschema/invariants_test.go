package adschema

import (
	"testing"

	"github.com/nemethhh/go-adpwsh/schema"
)

// The floors were measured against a stock Windows Server 2025 schema
// (corp.local, Windows2025Forest, objectVersion 91, 1,507 attributes, 270
// classes) on 2026-08-20. They are floors, not equalities: a schema only ever
// grows, and an extended forest legitimately reports more.
var effectiveFloor = map[string]int{
	"organizationalUnit": 160,
	"group":              192,
	"user":               406,
}

// checkInvariants asserts everything that must be true of any catalog, from any
// forest. It is called with a freshly exported catalog by the lab test and with
// the committed baseline by a test that needs no domain — one set of
// assertions, two backends, which is what detects a divergence between them.
func checkInvariants(t *testing.T, cat *schema.Catalog) {
	t.Helper()

	if cat.Source.Domain == "" || cat.Source.SchemaNC == "" || cat.Source.ForestMode == "" {
		t.Errorf("provenance is incomplete: %+v", cat.Source)
	}
	if cat.Source.ObjectVersion <= 0 {
		t.Errorf("objectVersion = %d, want a positive schema version", cat.Source.ObjectVersion)
	}
	if cat.Source.Exporter != exporterID {
		t.Errorf("exporter = %q, want %q", cat.Source.Exporter, exporterID)
	}

	// Every attribute named by every class exists in the attribute map. An
	// attribute named but absent means a partial fetch, and a consumer that
	// tolerated it would under-report.
	if err := cat.Validate(); err != nil {
		t.Errorf("the catalog is inconsistent: %v", err)
	}

	if sam, ok := cat.Attributes["sAMAccountName"]; !ok {
		t.Error("sAMAccountName is missing from the attribute map")
	} else {
		if !sam.SingleValued {
			t.Error("sAMAccountName must be single-valued")
		}
		if sam.RangeUpper == nil || *sam.RangeUpper != 256 {
			t.Errorf("sAMAccountName rangeUpper = %v, want 256", sam.RangeUpper)
		}
	}

	// Forward links are even and a back-link is its forward link plus one, so
	// this pins the pairing rather than merely the presence of a number.
	member, memberOK := cat.Attributes["member"]
	memberOf, memberOfOK := cat.Attributes["memberOf"]
	switch {
	case !memberOK || !memberOfOK:
		t.Error("member and memberOf must both be present")
	case member.LinkID == nil || memberOf.LinkID == nil:
		t.Errorf("member linkId = %v, memberOf linkId = %v; both must be linked",
			member.LinkID, memberOf.LinkID)
	default:
		if *member.LinkID != 2 || *memberOf.LinkID != 3 {
			t.Errorf("member/memberOf linkIds = %d/%d, want 2/3", *member.LinkID, *memberOf.LinkID)
		}
		if *member.LinkID%2 != 0 || *memberOf.LinkID != *member.LinkID+1 {
			t.Errorf("linkIds %d/%d break the forward-even, back-link-plus-one pairing",
				*member.LinkID, *memberOf.LinkID)
		}
	}

	for _, name := range []string{"objectSid", "memberOf"} {
		a, ok := cat.Attributes[name]
		if !ok {
			t.Errorf("%s is missing from the attribute map", name)
			continue
		}
		if !a.SystemOnly {
			t.Errorf("%s must be systemOnly", name)
		}
	}

	for class, floor := range effectiveFloor {
		cl, ok := cat.Classes[class]
		if !ok {
			t.Errorf("class %s is missing from the catalog", class)
			continue
		}
		if got := len(cl.Mandatory) + len(cl.Optional); got < floor {
			t.Errorf("class %s has %d effective attributes, want at least the measured %d — "+
				"a closure that under-reports rejects attributes AD accepts", class, got, floor)
		}
		if !cl.Structural {
			t.Errorf("class %s must be structural", class)
		}
		if len(cl.Mandatory) == 0 {
			t.Errorf("class %s has no mandatory attributes; cn and objectClass at least must be", class)
		}
	}

	// Every assertion above only ever catches under-reporting: a closure that
	// over-unions — worst case, every class's Optional listing every attribute
	// in the schema — would pass every one of them, since Validate only checks
	// that named attributes exist and via entries pair up, and the floors above
	// succeed by being exceeded. organizationalUnit is a container, never a
	// security principal, so a user-only attribute like sAMAccountName must
	// never appear in its effective set in any forest, stock or extended. This
	// is the one check in this function that fails if the closure unions too
	// much rather than too little.
	if ou, ok := cat.Classes["organizationalUnit"]; ok {
		effective := make(map[string]bool, len(ou.Mandatory)+len(ou.Optional))
		for _, group := range [][]string{ou.Mandatory, ou.Optional} {
			for _, attr := range group {
				effective[attr] = true
			}
		}
		if effective["sAMAccountName"] {
			t.Error("organizationalUnit's effective set names sAMAccountName, a user-only attribute — " +
				"the closure is over-unioning rather than following the schema")
		}
	}
}

// TestBaselineMeetsTheInvariants runs the same assertions as the lab export
// against the catalog committed with this module. It needs no domain, so it
// runs in CI on every change: a hand edit, a bad merge or a regeneration that
// lost half the schema fails here rather than in a consumer.
func TestBaselineMeetsTheInvariants(t *testing.T) {
	cat, err := schema.Baseline()
	if err != nil {
		t.Fatalf("schema.Baseline(): %v", err)
	}
	checkInvariants(t, cat)

	// The committed baseline is the stock schema, so its own numbers are known
	// exactly rather than as a floor. These are the two facts a regeneration
	// against a *different* forest would legitimately change, so a failure here
	// is a prompt to check the provenance, not necessarily a bug.
	if got := len(cat.Attributes); got < 1500 {
		t.Errorf("the baseline carries %d attributes; a stock Windows Server 2025 schema has about 1,507", got)
	}
	if cat.Source.Domain == "" || cat.Source.ExportedAt == "" {
		t.Errorf("the committed baseline must carry its provenance: %+v", cat.Source)
	}
}
