package adschema

import (
	"sort"
	"strings"
	"testing"
)

// The fixtures are hand-built rather than captured from a dump: the closure is
// the part that can be wrong in ways nobody notices, and a fixture states the
// shape it must get right.

func attrs(names ...string) []RawAttribute {
	out := make([]RawAttribute, 0, len(names))
	for _, n := range names {
		out = append(out, RawAttribute{Name: n, OID: "1.2.3", Syntax: "2.5.5.12"})
	}
	return out
}

func effective(t *testing.T, raw *Raw, class string) (mandatory, optional []string, via map[string]string) {
	t.Helper()
	got, err := Resolve(raw, []string{class})
	if err != nil {
		t.Fatalf("Resolve(%s): %v", class, err)
	}
	c, ok := got[class]
	if !ok {
		t.Fatalf("Resolve returned no class %q (got %v)", class, got)
	}
	return c.Mandatory, c.Optional, c.Via
}

// A linear chain: top -> person -> organizationalPerson -> user. Every ancestor
// contributes, and via names the class that did.
func TestResolveWalksALinearChain(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn", "objectClass", "sn", "telephoneNumber", "sAMAccountName"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMustContain: []string{"objectClass"}, SystemMayContain: []string{"cn"}},
			{Name: "person", Category: 1, SubClassOf: "top", MustContain: []string{"sn"}},
			{Name: "organizationalPerson", Category: 1, SubClassOf: "person", MayContain: []string{"telephoneNumber"}},
			{Name: "user", Category: 1, SubClassOf: "organizationalPerson", MayContain: []string{"sAMAccountName"}},
		},
	}
	mandatory, optional, via := effective(t, raw, "user")
	if want := []string{"objectClass", "sn"}; !equal(mandatory, want) {
		t.Errorf("mandatory = %v, want %v", mandatory, want)
	}
	if want := []string{"cn", "sAMAccountName", "telephoneNumber"}; !equal(optional, want) {
		t.Errorf("optional = %v, want %v", optional, want)
	}
	for attr, wantVia := range map[string]string{
		"objectClass": "top", "cn": "top", "sn": "person",
		"telephoneNumber": "organizationalPerson", "sAMAccountName": "user",
	} {
		if via[attr] != wantVia {
			t.Errorf("via[%s] = %q, want %q", attr, via[attr], wantVia)
		}
	}
}

// An auxiliary class contributes to a class that does not inherit it
// structurally, and its own parents contribute too.
func TestResolveFollowsAuxiliaryClassesAndTheirParents(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn", "mail", "textEncodedORAddress", "member"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}},
			{Name: "mailRecipientBase", Category: 3, SubClassOf: "top", MayContain: []string{"textEncodedORAddress"}},
			{Name: "mailRecipient", Category: 3, SubClassOf: "mailRecipientBase", MayContain: []string{"mail"}},
			{Name: "group", Category: 1, SubClassOf: "top", AuxiliaryClass: []string{"mailRecipient"}, MayContain: []string{"member"}},
		},
	}
	_, optional, via := effective(t, raw, "group")
	if want := []string{"cn", "mail", "member", "textEncodedORAddress"}; !equal(optional, want) {
		t.Errorf("optional = %v, want %v", optional, want)
	}
	if via["mail"] != "mailRecipient" || via["textEncodedORAddress"] != "mailRecipientBase" {
		t.Errorf("via = %v", via)
	}
}

// A diamond: one auxiliary class is reachable by two paths. Every attribute
// appears once, and the recorded contributor is deterministic — nearest first,
// then name ascending.
func TestResolveDeduplicatesADiamond(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn", "shared"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}},
			{Name: "securityPrincipal", Category: 3, SubClassOf: "top", MayContain: []string{"shared"}},
			// Both auxiliaries pull in securityPrincipal, and both sit one step
			// from user, so the tie-break by name decides.
			{Name: "bAux", Category: 3, SubClassOf: "top", AuxiliaryClass: []string{"securityPrincipal"}, MayContain: []string{"shared"}},
			{Name: "aAux", Category: 3, SubClassOf: "top", AuxiliaryClass: []string{"securityPrincipal"}, MayContain: []string{"shared"}},
			{Name: "user", Category: 1, SubClassOf: "top", AuxiliaryClass: []string{"bAux", "aAux"}},
		},
	}
	_, optional, via := effective(t, raw, "user")
	if want := []string{"cn", "shared"}; !equal(optional, want) {
		t.Errorf("optional = %v, want %v (an attribute must appear once)", optional, want)
	}
	if via["shared"] != "aAux" {
		t.Errorf("via[shared] = %q, want aAux (nearest wins; ties break by name ascending)", via["shared"])
	}
	// Run it again: the answer must not depend on map iteration order.
	for i := 0; i < 20; i++ {
		if _, _, again := effective(t, raw, "user"); again["shared"] != "aAux" {
			t.Fatalf("via[shared] = %q on iteration %d; the tie-break is not deterministic", again["shared"], i)
		}
	}
}

// top is its own subClassOf, so the walk terminates on a visited-set rather
// than on reaching a root.
func TestResolveTerminatesOnTopsSelfReference(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}, AuxiliaryClass: []string{"top"}},
		},
	}
	_, optional, _ := effective(t, raw, "top")
	if want := []string{"cn"}; !equal(optional, want) {
		t.Errorf("optional = %v, want %v", optional, want)
	}
}

// An attribute a class names but the fetch did not return means a partial
// fetch. A retry loop would paper over it, so it is fatal rather than a silent
// omission.
func TestResolveRejectsAnAttributeMissingFromTheMap(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}},
			{Name: "user", Category: 1, SubClassOf: "top", MayContain: []string{"ghostAttribute"}},
		},
	}
	_, err := Resolve(raw, []string{"user"})
	if err == nil || !strings.Contains(err.Error(), "ghostAttribute") {
		t.Fatalf("want a fatal error naming ghostAttribute, got %v", err)
	}
}

// The same reasoning for a class: a subClassOf or auxiliaryClass that is absent
// from the fetch is the same partial fetch.
func TestResolveRejectsAClassMissingFromTheMap(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes: []RawClass{
			{Name: "user", Category: 1, SubClassOf: "ghostClass", MayContain: []string{"cn"}},
		},
	}
	_, err := Resolve(raw, []string{"user"})
	if err == nil || !strings.Contains(err.Error(), "ghostClass") {
		t.Fatalf("want a fatal error naming ghostClass, got %v", err)
	}
}

// A class named in --classes that does not exist is the tool's other named
// failure.
func TestResolveRejectsAnUnknownRequestedClass(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes:    []RawClass{{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}}},
	}
	_, err := Resolve(raw, []string{"nosuchclass"})
	if err == nil || !strings.Contains(err.Error(), "nosuchclass") {
		t.Fatalf("want a fatal error naming the class, got %v", err)
	}
}

// LDAP names are case-insensitive, and the schema does not guarantee that a
// mayContain value matches the attribute's own lDAPDisplayName byte for byte.
// A case difference must resolve to the canonical name, not fire the
// partial-fetch error.
func TestResolveFoldsCaseAndEmitsCanonicalNames(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("sAMAccountName"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top"},
			{Name: "user", Category: 1, SubClassOf: "TOP", MayContain: []string{"samaccountname"}},
		},
	}
	got, err := Resolve(raw, []string{"USER"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cl, ok := got["user"]
	if !ok {
		t.Fatalf("the emitted key must be the schema's own name, not the one asked for: %v", got)
	}
	if want := []string{"sAMAccountName"}; !equal(cl.Optional, want) {
		t.Errorf("optional = %v, want the canonical %v", cl.Optional, want)
	}
	if cl.Via["sAMAccountName"] != "user" {
		t.Errorf("via = %v", cl.Via)
	}
}

// A must-contain cannot be relaxed by a class that also lists the attribute as
// may-contain, and an attribute must appear in exactly one of the two lists.
func TestResolveMandatoryWinsOverOptional(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes: []RawClass{
			{Name: "top", Category: 2, SubClassOf: "top", SystemMustContain: []string{"cn"}},
			{Name: "user", Category: 1, SubClassOf: "top", MayContain: []string{"cn"}},
		},
	}
	mandatory, optional, _ := effective(t, raw, "user")
	if !equal(mandatory, []string{"cn"}) || len(optional) != 0 {
		t.Errorf("mandatory = %v, optional = %v; a must-contain cannot be relaxed", mandatory, optional)
	}
}

// Empty lists serialise as [] rather than null: a null/[] flip would make a
// diff unreadable for no reason.
func TestResolveEmitsEmptySlicesNotNil(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes:    []RawClass{{Name: "top", Category: 2, SubClassOf: "top", SystemMayContain: []string{"cn"}}},
	}
	mandatory, _, _ := effective(t, raw, "top")
	if mandatory == nil {
		t.Error("Mandatory must be an empty slice, not nil")
	}
}

func TestAllStructuralReturnsOnlyStructuralClassesSorted(t *testing.T) {
	raw := &Raw{
		Attributes: attrs("cn"),
		Classes: []RawClass{
			{Name: "user", Category: 1, SubClassOf: "top"},
			{Name: "top", Category: 2, SubClassOf: "top"},
			{Name: "group", Category: 1, SubClassOf: "top"},
			{Name: "mailRecipient", Category: 3, SubClassOf: "top"},
		},
	}
	if got, want := AllStructural(raw), []string{"group", "user"}; !equal(got, want) {
		t.Errorf("AllStructural() = %v, want %v", got, want)
	}
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]string(nil), got...)
	sort.Strings(g)
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}
