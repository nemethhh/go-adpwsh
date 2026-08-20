package schema_test

import (
	"strings"
	"testing"

	"github.com/nemethhh/go-adpwsh/schema"
)

const minimalCatalog = `{
  "source": {
    "domain": "corp.local",
    "forestMode": "Windows2025Forest",
    "schemaNC": "CN=Schema,CN=Configuration,DC=corp,DC=local",
    "objectVersion": 91,
    "exportedAt": "2026-08-20T10:41:00Z",
    "exporter": "adschema/1"
  },
  "attributes": {
    "cn":             {"oid": "2.5.4.3", "syntax": "2.5.5.12", "omSyntax": 64, "singleValued": true, "systemOnly": false, "rangeUpper": 64, "indexed": true, "linkId": null},
    "sAMAccountName": {"oid": "1.2.840.113556.1.4.221", "syntax": "2.5.5.12", "omSyntax": 64, "singleValued": true, "systemOnly": false, "rangeLower": 0, "rangeUpper": 256, "indexed": true, "linkId": null},
    "member":         {"oid": "1.2.840.113556.1.4.31", "syntax": "2.5.5.1", "omSyntax": 127, "singleValued": false, "systemOnly": false, "indexed": false, "linkId": 2}
  },
  "classes": {
    "group": {
      "structural": true,
      "mandatory": ["cn", "sAMAccountName"],
      "optional":  ["member"],
      "via": {"cn": "top", "sAMAccountName": "group", "member": "group"}
    }
  }
}`

func TestLoadReadsEveryField(t *testing.T) {
	cat, err := schema.Load(strings.NewReader(minimalCatalog))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cat.Source.ObjectVersion != 91 || cat.Source.Domain != "corp.local" {
		t.Errorf("source = %+v", cat.Source)
	}
	sam := cat.Attributes["sAMAccountName"]
	if !sam.SingleValued || sam.OMSyntax != 64 || !sam.Indexed {
		t.Errorf("sAMAccountName = %+v", sam)
	}
	if sam.RangeUpper == nil || *sam.RangeUpper != 256 {
		t.Errorf("sAMAccountName rangeUpper = %v, want 256", sam.RangeUpper)
	}
	// An omitted bound and an explicit null mean the same thing: the schema
	// states no bound.
	if cn := cat.Attributes["cn"]; cn.RangeLower != nil {
		t.Errorf("cn rangeLower = %v, want nil", cn.RangeLower)
	}
	if m := cat.Attributes["member"]; m.LinkID == nil || *m.LinkID != 2 {
		t.Errorf("member linkId = %v, want 2", m.LinkID)
	}
	if got := cat.ClassNames(); len(got) != 1 || got[0] != "group" {
		t.Errorf("ClassNames() = %v", got)
	}
}

// A class naming an attribute the catalog does not carry is a partial export.
// A consumer that ignored it would under-report exactly the way a naive
// exporter does, so the reader refuses it.
func TestLoadRejectsAClassNamingAnAbsentAttribute(t *testing.T) {
	broken := strings.Replace(minimalCatalog, `"optional":  ["member"]`, `"optional":  ["member", "ghostAttribute"]`, 1)
	_, err := schema.Load(strings.NewReader(broken))
	if err == nil {
		t.Fatal("Load must reject a class naming an absent attribute")
	}
	if !strings.Contains(err.Error(), "ghostAttribute") {
		t.Errorf("the error must name the attribute: %v", err)
	}
}

// via is the diagnostic that makes the closure reviewable. An attribute with no
// via entry, or a via entry for an attribute the class does not name, is a bug
// in whatever produced the file.
func TestValidateChecksViaBothWays(t *testing.T) {
	noVia := strings.Replace(minimalCatalog, `"cn": "top", `, "", 1)
	if _, err := schema.Load(strings.NewReader(noVia)); err == nil || !strings.Contains(err.Error(), "via") {
		t.Errorf("a missing via entry must be an error: %v", err)
	}
	strayVia := strings.Replace(minimalCatalog, `"member": "group"`, `"member": "group", "cn2": "top"`, 1)
	if _, err := schema.Load(strings.NewReader(strayVia)); err == nil || !strings.Contains(err.Error(), "cn2") {
		t.Errorf("a stray via entry must be an error: %v", err)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	if _, err := schema.Load(strings.NewReader("{oh no")); err == nil {
		t.Fatal("Load must reject malformed JSON")
	}
}
