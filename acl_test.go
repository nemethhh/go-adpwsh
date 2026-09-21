package adpwsh

import (
	"testing"
)

func TestInheritanceCmdletValue(t *testing.T) {
	cases := map[Inheritance]string{
		InheritanceThis:        "None",
		InheritanceDescendants: "Descendents",
		InheritanceChildren:    "Children",
	}
	for in, want := range cases {
		got, ok := cmdletInheritance(in)
		if !ok || got != want {
			t.Errorf("cmdletInheritance(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	if _, ok := cmdletInheritance(Inheritance("bogus")); ok {
		t.Error("bogus inheritance accepted")
	}
}
