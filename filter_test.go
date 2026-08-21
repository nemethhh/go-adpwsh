package adpwsh

import "testing"

func TestEscapeFilterEscapesTheSpecialSet(t *testing.T) {
	if got := EscapeFilter("a*b(c)\\d"); got != `a\2ab\28c\29\5cd` {
		t.Fatalf("EscapeFilter = %q", got)
	}
}

func TestEqualEscapesTheValueNotTheAttr(t *testing.T) {
	if got := Equal("department", "R&D (EMEA)"); got != `(department=R&D \28EMEA\29)` {
		t.Fatalf("Equal = %q", got)
	}
}

func TestAndComposition(t *testing.T) {
	if got := And(); got != "" {
		t.Fatalf("And() = %q, want empty", got)
	}
	if got := And("(a=1)"); got != "(a=1)" {
		t.Fatalf("And(one) = %q, want the term unwrapped", got)
	}
	if got := And("(a=1)", "(b=2)"); got != "(&(a=1)(b=2))" {
		t.Fatalf("And(two) = %q", got)
	}
}
