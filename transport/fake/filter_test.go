package fake

import "testing"

func obj(data map[string]any) *DirectoryObject {
	return &DirectoryObject{Class: "user", DN: "CN=x,DC=corp,DC=local", Data: data}
}

func TestMatchFilterEquality(t *testing.T) {
	o := obj(map[string]any{"samAccountName": "jdoe", "description": "R&D"})
	for _, tc := range []struct {
		filter string
		want   bool
	}{
		{"(sAMAccountName=jdoe)", true},
		{"(sAMAccountName=other)", false},
		{`(description=R&D)`, true},     // no special chars
		{"(description=*)", true},       // presence
		{"(title=*)", false},            // absent attribute
		{"(sAMAccountName=j*)", true},   // trailing wildcard
		{"(sAMAccountName=*doe)", true}, // leading wildcard
		{"(sAMAccountName=*do*)", true}, // contains
		{"(&(sAMAccountName=jdoe)(description=R&D))", true},
		{"(&(sAMAccountName=jdoe)(description=nope))", false},
		{"(|(sAMAccountName=nope)(description=R&D))", true},
		{"(!(sAMAccountName=nope))", true},
	} {
		got, err := matchFilter(o, tc.filter)
		if err != nil {
			t.Fatalf("%s: %v", tc.filter, err)
		}
		if got != tc.want {
			t.Fatalf("matchFilter(%s) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

func TestMatchFilterUnescapesValues(t *testing.T) {
	o := obj(map[string]any{"description": "R&D (EMEA)"})
	// The provider emits (description=R&D \28EMEA\29) via EscapeFilter.
	got, err := matchFilter(o, `(description=R&D \28EMEA\29)`)
	if err != nil || !got {
		t.Fatalf("escaped value did not match: got=%v err=%v", got, err)
	}
}

func TestMatchFilterRejectsUnsupportedGrammar(t *testing.T) {
	// Approximate-match is outside the fake's grammar; it must error, not
	// silently mis-answer.
	if _, err := matchFilter(obj(map[string]any{}), "(x~=y)"); err == nil {
		t.Fatal("expected an error for unsupported operator")
	}
}
