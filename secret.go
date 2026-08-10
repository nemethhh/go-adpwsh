package adpwsh

import (
	"encoding/json"
	"errors"
)

// Secret carries a password without letting it reach a log line, a state file,
// or a %v verb. Its plaintext is readable only inside this package, through
// reveal, which the payload builders call deliberately at the moment of
// serialization. This is the structural answer to the archived provider's
// credential leak: the guarantee is on the type, not on each call site.
type Secret struct {
	v string
}

// NewSecret wraps a plaintext password.
func NewSecret(s string) Secret { return Secret{v: s} }

// String makes %v, %s and the print helpers safe.
func (Secret) String() string { return "REDACTED" }

// GoString makes %#v safe.
func (Secret) GoString() string { return "adpwsh.Secret{REDACTED}" }

// MarshalJSON always fails. A Secret must be revealed deliberately by a payload
// builder; it must never be serialized by a struct walk into a log line or a
// state file.
func (Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("adpwsh: Secret must not be marshalled; the payload builder reveals it deliberately")
}

// IsZero reports whether the secret was never set.
func (s Secret) IsZero() bool { return s.v == "" }

// reveal is the single in-package accessor for the plaintext.
func (s Secret) reveal() string { return s.v }

var _ json.Marshaler = Secret{}
