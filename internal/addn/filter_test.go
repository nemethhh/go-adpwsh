package addn

import "testing"

// Vectors ported from github.com/go-ldap/ldap (MIT). RFC 4515 requires
// (, ), *, \ and any byte outside 0 < c < 0x80 to be escaped as \XX.
func TestEscapeFilter(t *testing.T) {
	tests := []struct{ in, want string }{
		{"jdoe", "jdoe"},
		{"a*b", `a\2ab`},
		{"a(b)c", `a\28b\29c`},
		{`a\b`, `a\5cb`},
		{"Lučić", `Lu\c4\8di\c4\87`},
		{"Bob \x00", `Bob \00`},
		{"O'Brien, \"Bob\"", `O'Brien, "Bob"`},
	}
	for _, tt := range tests {
		if got := EscapeFilter(tt.in); got != tt.want {
			t.Errorf("EscapeFilter(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
