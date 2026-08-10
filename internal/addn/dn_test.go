// Package addn implements the small slice of RFC 4514 and RFC 4515 this
// library needs. The test vectors are ported from github.com/go-ldap/ldap
// (MIT) so the reimplementation is pinned to a maintained parser's behaviour.
package addn

import "testing"

func TestParseDN(t *testing.T) {
	tests := []struct {
		in   string
		want [][]AttributeTypeAndValue // one slice per RDN
	}{
		{"", nil},
		{"UID=jsmith,DC=example,DC=net", [][]AttributeTypeAndValue{
			{{"UID", "jsmith"}}, {{"DC", "example"}}, {{"DC", "net"}},
		}},
		{"OU=Sales+CN=J. Smith,DC=example,DC=net", [][]AttributeTypeAndValue{
			{{"OU", "Sales"}, {"CN", "J. Smith"}}, {{"DC", "example"}}, {{"DC", "net"}},
		}},
		{`CN=James \"Jim\" Smith\, III,DC=example,DC=net`, [][]AttributeTypeAndValue{
			{{"CN", `James "Jim" Smith, III`}}, {{"DC", "example"}}, {{"DC", "net"}},
		}},
		{`cn=Jim\2C \22Hasse Hö\22 Hansson!,dc=dummy,dc=com`, [][]AttributeTypeAndValue{
			{{"cn", `Jim, "Hasse Hö" Hansson!`}}, {{"dc", "dummy"}}, {{"dc", "com"}},
		}},
		{`CN=Lu\C4\8Di\C4\87`, [][]AttributeTypeAndValue{{{"CN", "Lučić"}}}},
		{`  CN  =  Lu\C4\8Di\C4\87  `, [][]AttributeTypeAndValue{{{"CN", "Lučić"}}}},
		{"A = 88  \t", [][]AttributeTypeAndValue{{{"A", "88  \t"}}}},
		{`cn=john.doe\;weird name,dc=example,dc=net`, [][]AttributeTypeAndValue{
			{{"cn", "john.doe;weird name"}}, {{"dc", "example"}}, {{"dc", "net"}},
		}},
		{`cn=\ John Doe`, [][]AttributeTypeAndValue{{{"cn", " John Doe"}}}},
		{`cn=John Doe\ `, [][]AttributeTypeAndValue{{{"cn", "John Doe "}}}},
		{`cn=John Doe\20`, [][]AttributeTypeAndValue{{{"cn", "John Doe "}}}},
		// The case AD actually produces for an OU holding a comma.
		{`OU=Sales\, EMEA,DC=corp,DC=local`, [][]AttributeTypeAndValue{
			{{"OU", "Sales, EMEA"}}, {{"DC", "corp"}}, {{"DC", "local"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			dn, err := ParseDN(tt.in)
			if err != nil {
				t.Fatalf("ParseDN(%q) = error %v", tt.in, err)
			}
			if len(dn.RDNs) != len(tt.want) {
				t.Fatalf("ParseDN(%q) produced %d RDNs, want %d: %+v", tt.in, len(dn.RDNs), len(tt.want), dn.RDNs)
			}
			for i, wantAttrs := range tt.want {
				got := dn.RDNs[i].Attributes
				if len(got) != len(wantAttrs) {
					t.Fatalf("RDN %d has %d attributes, want %d: %+v", i, len(got), len(wantAttrs), got)
				}
				for j, want := range wantAttrs {
					if got[j] != want {
						t.Errorf("RDN %d attribute %d = %+v, want %+v", i, j, got[j], want)
					}
				}
			}
		})
	}
}

func TestParseDNErrors(t *testing.T) {
	for _, in := range []string{
		"CN",                           // no '='
		`CN=x\`,                        // dangling escape
		`CN=x\Z1`,                      // bad hex
		"1.3.6.1.4.1.1466.0=#04024869", // BER value: rejected, not decoded
	} {
		if _, err := ParseDN(in); err == nil {
			t.Errorf("ParseDN(%q) succeeded; want an error", in)
		}
	}
}

func TestEqualFoldAndAncestor(t *testing.T) {
	// AD echoes DNs back in its own case and spacing; a raw string compare
	// would manufacture a diff on every refresh.
	same := []struct{ a, b string }{
		{"OU=Staff,DC=corp,DC=local", "ou=staff,dc=CORP,dc=Local"},
		{"OU=Staff, DC=corp, DC=local", "OU=Staff,DC=corp,DC=local"},
		{`OU=Sales\, EMEA,DC=corp,DC=local`, `ou=sales\, emea,dc=corp,dc=local`},
	}
	for _, tt := range same {
		a, err := ParseDN(tt.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseDN(tt.b)
		if err != nil {
			t.Fatal(err)
		}
		if !a.EqualFold(b) {
			t.Errorf("%q should equal %q", tt.a, tt.b)
		}
	}

	parent, _ := ParseDN("DC=corp,DC=local")
	child, _ := ParseDN("CN=jdoe,OU=Staff,DC=corp,DC=local")
	if !parent.AncestorOfFold(child) {
		t.Error("DC=corp,DC=local should be an ancestor of the user DN")
	}
	if child.AncestorOfFold(parent) {
		t.Error("ancestry must not be symmetric")
	}
	if parent.AncestorOfFold(parent) {
		t.Error("a DN is not its own ancestor")
	}
}

func TestParent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"CN=jdoe,OU=Staff,DC=corp,DC=local", "OU=Staff,DC=corp,DC=local"},
		{`CN=Smith\, John,OU=Staff,DC=corp,DC=local`, "OU=Staff,DC=corp,DC=local"},
		{"DC=local", ""},
	}
	for _, tt := range tests {
		got, err := Parent(tt.in)
		if err != nil {
			t.Fatalf("Parent(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("Parent(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// String must round-trip through ParseDN, because Parent rebuilds a DN from
// parsed components and hands it to Move-ADObject as -TargetPath.
func TestStringRoundTrip(t *testing.T) {
	for _, in := range []string{
		"CN=jdoe,OU=Staff,DC=corp,DC=local",
		`CN=Smith\, John,OU=Sales \+ Marketing,DC=corp,DC=local`,
		`CN=a\=b,DC=corp`,
	} {
		dn, err := ParseDN(in)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", in, err)
		}
		again, err := ParseDN(dn.String())
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", dn.String(), err)
		}
		if !dn.EqualFold(again) {
			t.Errorf("round trip changed %q into %q", in, dn.String())
		}
	}
}
