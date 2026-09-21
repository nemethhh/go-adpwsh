package adpwsh

import (
	"errors"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// applyStringField encodes one tri-state string field: nil leaves it alone,
// "" clears it through -Clear (AD has no empty attribute value), anything else
// sets the cmdlet parameter.
func applyStringField(ops *adscript.AttrOps, splat map[string]any, param, ldapName string, v *string) {
	if v == nil {
		return
	}
	if *v == "" {
		ops.ClearName(ldapName)
		return
	}
	splat[param] = *v
}

// conflictToError converts the payload builder's refusal into the library's
// error type. adscript stays dependency-free, so the translation lives here.
func conflictToError(op string, err error) error {
	if err == nil {
		return nil
	}
	var ce *adscript.ConflictError
	if errors.As(err, &ce) {
		return &Error{Kind: KindConstraint, Op: op, Err: ce}
	}
	return &Error{Kind: KindConstraint, Op: op, Err: err}
}

// userTier1 is the hand-written field → (cmdlet parameter, LDAP name) mapping.
// Fifteen rows per resource is a table, not a generator's job; the lab's
// Get-Command fixture asserts the parameter names against the installed module.
// Surname's LDAP name is sn, which is the row this table exists for.
var userTier1 = []struct {
	Param string
	LDAP  string
	Get   func(UserSpec) *string
}{
	{"UserPrincipalName", "userPrincipalName", func(s UserSpec) *string { return s.UserPrincipalName }},
	{"DisplayName", "displayName", func(s UserSpec) *string { return s.DisplayName }},
	{"GivenName", "givenName", func(s UserSpec) *string { return s.GivenName }},
	{"Surname", "sn", func(s UserSpec) *string { return s.Surname }},
	{"Description", "description", func(s UserSpec) *string { return s.Description }},
}

var errEmptyPassword = errors.New("an empty password cannot be set")
