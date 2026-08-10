package adpwsh

// Identity is an AD -Identity argument. The interface is sealed by an
// unexported method: the only values that satisfy it come from the four
// constructors below, so there is no constructor taking an arbitrary string as
// an identity and no caller can hand the library a value that becomes script
// text.
type Identity interface {
	identityArg() string
	identityForm() string
	String() string
}

type identity struct {
	arg  string
	form string
}

func (i identity) identityArg() string  { return i.arg }
func (i identity) identityForm() string { return i.form }
func (i identity) String() string       { return i.form + ":" + i.arg }

// ByGUID identifies an object by objectGUID. This is the canonical form: it
// survives rename and move, which DN and sAMAccountName do not.
func ByGUID(guid string) Identity { return identity{arg: guid, form: "guid"} }

// ByDN identifies an object by distinguished name.
func ByDN(dn string) Identity { return identity{arg: dn, form: "dn"} }

// BySID identifies a security principal by SID.
func BySID(sid string) Identity { return identity{arg: sid, form: "sid"} }

// BySAM identifies a security principal by sAMAccountName.
func BySAM(sam string) Identity { return identity{arg: sam, form: "sam"} }
