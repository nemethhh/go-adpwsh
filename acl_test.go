package adpwsh

import "testing"

func TestInheritanceCmdletValue(t *testing.T) {
	cases := map[Inheritance]string{
		InheritanceThis:        "None",
		InheritanceDescendants: "Descendents",
		InheritanceChildren:    "Children",
	}
	for in, want := range cases {
		got, ok := in.cmdletValue()
		if !ok || got != want {
			t.Errorf("%q.cmdletValue() = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	if _, ok := Inheritance("bogus").cmdletValue(); ok {
		t.Error("bogus inheritance accepted")
	}
}

func TestCanonicalACEKeyStableAndOrderInsensitive(t *testing.T) {
	a := ACE{Trustee: "S-1-5-21-1", Type: ACEAllow, Rights: []Right{"WriteProperty", "ReadProperty"},
		ObjectType: "GUID-1", InheritedObjectType: "GUID-2", Inheritance: InheritanceDescendants}
	b := ACE{Trustee: "s-1-5-21-1", Type: ACEAllow, Rights: []Right{"ReadProperty", "WriteProperty"},
		ObjectType: "guid-1", InheritedObjectType: "guid-2", Inheritance: InheritanceDescendants}
	if canonicalACEKey(a) != canonicalACEKey(b) {
		t.Errorf("keys differ despite semantic equality:\n a=%s\n b=%s", canonicalACEKey(a), canonicalACEKey(b))
	}
	c := a
	c.Type = ACEDeny
	if canonicalACEKey(a) == canonicalACEKey(c) {
		t.Error("Allow and Deny produced the same key")
	}
}
