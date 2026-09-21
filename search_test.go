package adpwsh

import (
	"reflect"
	"testing"
)

func TestQueryWithDefaults(t *testing.T) {
	got := Query{}.WithDefaults("DC=corp,DC=local")
	if got.SearchBase != "DC=corp,DC=local" || got.Scope != SearchScopeSubtree || got.SizeLimit != 1000 {
		t.Fatalf("defaults = %+v", got)
	}
	// Explicit values win over defaults.
	q := Query{SearchBase: "OU=x,DC=corp,DC=local", Scope: SearchScopeOneLevel, SizeLimit: 5}
	if got := q.WithDefaults("DC=corp,DC=local"); !reflect.DeepEqual(got, q) {
		t.Fatalf("explicit values overridden: %+v", got)
	}
}

func TestQueryPayloadRequestsOneOverTheLimit(t *testing.T) {
	q := Query{Filter: "(department=Sales)", SearchBase: "DC=corp,DC=local", Scope: SearchScopeSubtree, SizeLimit: 10}
	p := queryPayload(q, []string{"Description"})
	if p["filter"] != "(department=Sales)" || p["searchBase"] != "DC=corp,DC=local" ||
		p["scope"] != "Subtree" || p["sizeLimit"] != 11 {
		t.Fatalf("payload = %+v", p)
	}
}

func TestQueryPayloadDefaultsEmptyFilterToObjectClassStar(t *testing.T) {
	if got := queryPayload(Query{SizeLimit: 1}, nil)["filter"]; got != "(objectClass=*)" {
		t.Fatalf("empty filter = %v", got)
	}
}

func TestKindTooManyResultsString(t *testing.T) {
	if KindTooManyResults.String() != "too many results" {
		t.Fatalf("String = %q", KindTooManyResults.String())
	}
	if KindTooManyResults.Retryable() {
		t.Fatal("too-many-results must not be retryable")
	}
}
