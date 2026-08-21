package adpwsh

import (
	"reflect"
	"testing"
)

func TestQueryWithDefaults(t *testing.T) {
	got := Query{}.withDefaults("DC=corp,DC=local")
	if got.SearchBase != "DC=corp,DC=local" || got.Scope != SearchScopeSubtree || got.SizeLimit != 1000 {
		t.Fatalf("defaults = %+v", got)
	}
	// Explicit values win over defaults.
	q := Query{SearchBase: "OU=x,DC=corp,DC=local", Scope: SearchScopeOneLevel, SizeLimit: 5}
	if got := q.withDefaults("DC=corp,DC=local"); !reflect.DeepEqual(got, q) {
		t.Fatalf("explicit values overridden: %+v", got)
	}
}

func TestQueryPayloadRequestsOneOverTheLimit(t *testing.T) {
	q := Query{Filter: "(department=Sales)", SearchBase: "DC=corp,DC=local", Scope: SearchScopeSubtree, SizeLimit: 10}
	p := q.payload([]string{"Description"})
	if p["filter"] != "(department=Sales)" || p["searchBase"] != "DC=corp,DC=local" ||
		p["scope"] != "Subtree" || p["sizeLimit"] != 11 {
		t.Fatalf("payload = %+v", p)
	}
}

func TestQueryPayloadDefaultsEmptyFilterToObjectClassStar(t *testing.T) {
	if got := (Query{SizeLimit: 1}).payload(nil)["filter"]; got != "(objectClass=*)" {
		t.Fatalf("empty filter = %v", got)
	}
}

func TestKindTooManyResultsString(t *testing.T) {
	if KindTooManyResults.String() != "too many results" {
		t.Fatalf("String = %q", KindTooManyResults.String())
	}
	if KindTooManyResults.retryable() {
		t.Fatal("too-many-results must not be retryable")
	}
}
