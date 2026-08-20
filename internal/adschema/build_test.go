package adschema

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden catalog")

func buildFixture() *Raw {
	i := func(n int) *int { return &n }
	return &Raw{
		Source: RawSource{
			Domain:        "corp.local",
			ForestMode:    "Windows2025Forest",
			SchemaNC:      "CN=Schema,CN=Configuration,DC=corp,DC=local",
			ObjectVersion: 91,
		},
		Attributes: []RawAttribute{
			// searchFlags 13 is 0b1101: bit 0 set, so indexed.
			{Name: "sAMAccountName", OID: "1.2.840.113556.1.4.221", Syntax: "2.5.5.12", OMSyntax: 64,
				SingleValued: true, RangeLower: i(0), RangeUpper: i(256), SearchFlags: 13},
			{Name: "member", OID: "1.2.840.113556.1.4.31", Syntax: "2.5.5.1", OMSyntax: 127,
				SingleValued: false, SearchFlags: 0, LinkID: i(2)},
			{Name: "memberOf", OID: "1.2.840.113556.1.2.102", Syntax: "2.5.5.1", OMSyntax: 127,
				SingleValued: false, SystemOnly: true, SearchFlags: 8, LinkID: i(3)},
			{Name: "cn", OID: "2.5.4.3", Syntax: "2.5.5.12", OMSyntax: 64,
				SingleValued: true, RangeUpper: i(64), SearchFlags: 1},
		},
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMustContain: []string{"cn"}, SystemMayContain: []string{"memberOf"}},
			{Name: "group", Category: 1, SubClassOf: "top", MustContain: []string{"sAMAccountName"}, MayContain: []string{"member"}},
		},
	}
}

func TestBuildReducesSearchFlagsAndKeepsAbsentBoundsAbsent(t *testing.T) {
	cat, err := Build(buildFixture(), []string{"group"}, time.Date(2026, 8, 20, 10, 41, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := cat.Attributes["sAMAccountName"]; !got.Indexed || got.RangeUpper == nil || *got.RangeUpper != 256 {
		t.Errorf("sAMAccountName = %+v", got)
	}
	// searchFlags 8 has bit 0 clear: not indexed, whatever else it says.
	if got := cat.Attributes["memberOf"]; got.Indexed || !got.SystemOnly {
		t.Errorf("memberOf = %+v", got)
	}
	// A linked attribute keeps its linkId; an unlinked one carries none.
	if got := cat.Attributes["member"]; got.LinkID == nil || *got.LinkID != 2 {
		t.Errorf("member linkId = %v, want 2", got.LinkID)
	}
	if got := cat.Attributes["cn"]; got.RangeLower != nil {
		t.Errorf("cn rangeLower = %v, want nil: the schema states no lower bound", got.RangeLower)
	}
	// Every attribute is carried, not only those the exported classes reach.
	if len(cat.Attributes) != 4 {
		t.Errorf("got %d attributes, want all 4", len(cat.Attributes))
	}
	if cat.Source.ExportedAt != "2026-08-20T10:41:00Z" || cat.Source.Exporter != "adschema/1" {
		t.Errorf("source = %+v", cat.Source)
	}
	if cat.Source.ObjectVersion != 91 || cat.Source.ForestMode != "Windows2025Forest" {
		t.Errorf("source = %+v", cat.Source)
	}
}

// A fractional second in the caller's clock must not leak into provenance: the
// timestamp is a value in a diff, so it has one shape.
func TestBuildFormatsTheTimestampToTheSecondInUTC(t *testing.T) {
	local := time.Date(2026, 8, 20, 12, 41, 30, 123456789, time.FixedZone("CEST", 2*60*60))
	cat, err := Build(buildFixture(), []string{"group"}, local)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cat.Source.ExportedAt != "2026-08-20T10:41:30Z" {
		t.Errorf("exportedAt = %q", cat.Source.ExportedAt)
	}
}

// Build must never return a catalog this module's own reader would reject: it
// would be committed and then fail on load, which is the worst possible moment
// to find out. Resolve refuses this input first; the Validate call in Build is
// the belt-and-braces behind it.
func TestBuildRefusesAnInconsistentSchema(t *testing.T) {
	raw := buildFixture()
	raw.Classes[1].MayContain = []string{"member", "ghostAttribute"}
	if _, err := Build(raw, []string{"group"}, time.Unix(0, 0).UTC()); err == nil {
		t.Fatal("Build must not return a catalog its own reader would reject")
	}
}

func TestEmitIsDeterministic(t *testing.T) {
	at := time.Date(2026, 8, 20, 10, 41, 0, 0, time.UTC)
	first, err := Build(buildFixture(), []string{"group", "top"}, at)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	a, err := Emit(first)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	for i := 0; i < 20; i++ {
		second, err := Build(buildFixture(), []string{"top", "group"}, at)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		b, err := Emit(second)
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("emit is not deterministic on iteration %d", i)
		}
	}
	if !bytes.HasSuffix(a, []byte("\n")) {
		t.Error("the file must end in exactly one newline")
	}
	if !strings.Contains(string(a), "\n  \"attributes\": {") {
		t.Error("the file must be indented with two spaces")
	}
}

// The emitted shape is a golden file, as the op scripts are, so a change to it
// is a reviewable diff rather than a surprise in a 300 kB data file.
func TestEmitGolden(t *testing.T) {
	cat, err := Build(buildFixture(), []string{"group", "top"}, time.Date(2026, 8, 20, 10, 41, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got, err := Emit(cat)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	path := filepath.Join("testdata", "golden", "catalog.json")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run: go test ./internal/adschema -run TestEmitGolden -update-golden)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the emitted catalog changed; diff %s against the new output", path)
	}
}
