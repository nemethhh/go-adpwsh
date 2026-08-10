// Package addn implements the slice of RFC 4514 (distinguished names) and
// RFC 4515 (search filters) this library needs: parsing and case-insensitive
// comparison of DNs, and escaping of filter assertion values.
//
// It is a reimplementation rather than a dependency on github.com/go-ldap/ldap,
// which would pull Kerberos, NTLM, SSPI and BER into a module that never dials
// LDAP. The test vectors are ported from that project (MIT licence).
package addn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AttributeTypeAndValue is one type=value pair inside an RDN.
type AttributeTypeAndValue struct {
	Type  string
	Value string
}

// RelativeDN is one comma-separated component; it holds more than one
// attribute only for the multi-valued (plus-joined) form.
type RelativeDN struct {
	Attributes []AttributeTypeAndValue
}

// DN is a parsed distinguished name, most specific RDN first.
type DN struct {
	RDNs []RelativeDN
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// escapableChars is RFC 4514 §3's pair production minus the hexpair branch:
//
//	pair    = ESC ( ESC / special / hexpair )
//	special = escaped / SPACE / SHARP / EQUALS
//	escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
//
// Anything else after a backslash is malformed. Accepting it — as a lenient
// parser would — turns "\Z1" into the literal "Z1" and silently changes the
// name of the object being addressed.
const escapableChars = `\"+,;<>= #`

// ParseDN parses the string form of a distinguished name. Hex-encoded BER
// attribute values (the "#04024869" form) are rejected rather than decoded:
// Active Directory never emits them, and decoding would require an ASN.1
// parser for no gain.
func ParseDN(str string) (*DN, error) {
	dn := &DN{}
	if strings.TrimSpace(str) == "" {
		return dn, nil
	}

	var (
		rdn      RelativeDN
		typeBuf  []byte
		valBuf   []byte
		hexBuf   []byte
		hasEq    bool
		escaping bool
		leading  bool // skipping the unescaped leading spaces of a value
		trailWS  int  // count of unescaped trailing spaces currently in valBuf
	)

	appendVal := func(b byte, escaped bool) {
		valBuf = append(valBuf, b)
		if b == ' ' && !escaped {
			trailWS++
		} else {
			trailWS = 0
		}
	}

	endAttr := func() error {
		if !hasEq {
			return fmt.Errorf("addn: RDN %q has no '='", string(typeBuf))
		}
		t := strings.TrimSpace(string(typeBuf))
		if t == "" {
			return errors.New("addn: empty attribute type")
		}
		rdn.Attributes = append(rdn.Attributes, AttributeTypeAndValue{
			Type:  t,
			Value: string(valBuf[:len(valBuf)-trailWS]),
		})
		typeBuf, valBuf, hasEq, trailWS = nil, nil, false, 0
		return nil
	}

	endRDN := func() error {
		if err := endAttr(); err != nil {
			return err
		}
		dn.RDNs = append(dn.RDNs, rdn)
		rdn = RelativeDN{}
		return nil
	}

	for i := 0; i < len(str); i++ {
		c := str[i]
		switch {
		case escaping:
			if isHexDigit(c) {
				hexBuf = append(hexBuf, c)
				if len(hexBuf) == 2 {
					b, err := strconv.ParseUint(string(hexBuf), 16, 8)
					if err != nil {
						return nil, fmt.Errorf("addn: bad hex escape %q in %q", hexBuf, str)
					}
					appendVal(byte(b), true)
					hexBuf, escaping, leading = nil, false, false
				}
				continue
			}
			if len(hexBuf) == 1 {
				return nil, fmt.Errorf("addn: incomplete hex escape in %q", str)
			}
			if strings.IndexByte(escapableChars, c) < 0 {
				return nil, fmt.Errorf("addn: %q is not an escapable character in %q", c, str)
			}
			appendVal(c, true)
			escaping, leading = false, false
		case !hasEq:
			if c == '=' {
				hasEq, leading = true, true
				continue
			}
			typeBuf = append(typeBuf, c)
		case c == '\\':
			escaping = true
		case c == ',' || c == ';':
			if err := endRDN(); err != nil {
				return nil, err
			}
			leading = false
		case c == '+':
			if err := endAttr(); err != nil {
				return nil, err
			}
			leading = true
		case c == ' ' && leading:
			// unescaped leading spaces are not part of the value
		case c == '#' && len(valBuf) == 0:
			return nil, fmt.Errorf("addn: hex-encoded BER value in %q is not supported", str)
		default:
			appendVal(c, false)
			leading = false
		}
	}
	if escaping || len(hexBuf) > 0 {
		return nil, fmt.Errorf("addn: dangling escape in %q", str)
	}
	if err := endRDN(); err != nil {
		return nil, err
	}
	return dn, nil
}

// String renders the DN in RFC 4514 form, escaping the characters that would
// otherwise change its structure.
func (d *DN) String() string {
	var sb strings.Builder
	for i, rdn := range d.RDNs {
		if i > 0 {
			sb.WriteByte(',')
		}
		for j, attr := range rdn.Attributes {
			if j > 0 {
				sb.WriteByte('+')
			}
			sb.WriteString(attr.Type)
			sb.WriteByte('=')
			sb.WriteString(escapeValue(attr.Value))
		}
	}
	return sb.String()
}

// EscapeValue is the exported spelling, for a caller that assembles an RDN
// instead of rendering a parsed DN. Building "OU=" + name + "," + parent by
// concatenation is correct right up to the first name containing a comma, at
// which point the name silently reparents the object.
func EscapeValue(v string) string { return escapeValue(v) }

// escapeValue applies RFC 4514 §2.4: the set ",+\"\\<>;=" is escaped
// everywhere, a leading '#' or space and a trailing space are escaped, and a
// NUL becomes \00.
func escapeValue(v string) string {
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == 0:
			sb.WriteString(`\00`)
		case strings.IndexByte(`,+"\<>;=`, c) >= 0:
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == ' ' && (i == 0 || i == len(v)-1):
			sb.WriteString(`\ `)
		case c == '#' && i == 0:
			sb.WriteString(`\#`)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// EqualFold reports whether two DNs name the same object, comparing attribute
// types and values case-insensitively. AD's DN syntax is case-insensitive and
// case-preserving, so this is the only correct comparison.
func (d *DN) EqualFold(other *DN) bool {
	if other == nil || len(d.RDNs) != len(other.RDNs) {
		return false
	}
	for i := range d.RDNs {
		if !d.RDNs[i].equalFold(&other.RDNs[i]) {
			return false
		}
	}
	return true
}

func (r *RelativeDN) equalFold(other *RelativeDN) bool {
	if len(r.Attributes) != len(other.Attributes) {
		return false
	}
	// Multi-valued RDNs are unordered.
	used := make([]bool, len(other.Attributes))
	for _, a := range r.Attributes {
		matched := false
		for j, b := range other.Attributes {
			if used[j] {
				continue
			}
			if strings.EqualFold(a.Type, b.Type) && strings.EqualFold(a.Value, b.Value) {
				used[j], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// AncestorOfFold reports whether d is a strict ancestor of other.
func (d *DN) AncestorOfFold(other *DN) bool {
	if other == nil || len(d.RDNs) >= len(other.RDNs) {
		return false
	}
	offset := len(other.RDNs) - len(d.RDNs)
	for i := range d.RDNs {
		if !d.RDNs[i].equalFold(&other.RDNs[i+offset]) {
			return false
		}
	}
	return true
}

// Parent returns the DN with its first RDN removed, or nil at the root.
func (d *DN) Parent() *DN {
	if len(d.RDNs) <= 1 {
		return nil
	}
	return &DN{RDNs: d.RDNs[1:]}
}

// Parent is the string convenience: it returns the container of dn, or "" if
// dn has no parent.
func Parent(dn string) (string, error) {
	parsed, err := ParseDN(dn)
	if err != nil {
		return "", err
	}
	p := parsed.Parent()
	if p == nil {
		return "", nil
	}
	return p.String(), nil
}

// EqualFold is the string convenience used wherever a spec value meets a value
// AD echoed back.
func EqualFold(a, b string) (bool, error) {
	pa, err := ParseDN(a)
	if err != nil {
		return false, err
	}
	pb, err := ParseDN(b)
	if err != nil {
		return false, err
	}
	return pa.EqualFold(pb), nil
}
