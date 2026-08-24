package adpwsh

import (
	"errors"
	"fmt"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// OUSpec is the desired state of an organizational unit. A nil pointer leaves
// the attribute alone; a pointer to "" clears it; a pointer to a value sets it.
type OUSpec struct {
	Name        string // the RDN; required on create, a change means Rename-ADObject
	Container   string // parent DN; required on create, a change means Move-ADObject
	Description *string
	Protected   *bool // ProtectedFromAccidentalDeletion
}

// DeleteOptions is taken only by OU.Delete. Making the unprotect step an
// explicit option keeps the destructive part visible at the call site.
type DeleteOptions struct {
	// Unprotect lifts ProtectedFromAccidentalDeletion before deleting. Without
	// it, deleting an OU created with AD's own default fails.
	Unprotect bool
}

func validateContainer(op, container string) error {
	if container == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is required")}
	}
	if _, err := addn.ParseDN(container); err != nil {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is not a distinguished name: %w", err)}
	}
	return nil
}

func validateName(op, name string) error {
	if name == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Name is required")}
	}
	return nil
}

// containerOf returns the parent of a DN, which is what the models expose as
// Container. Deriving it means the model and the directory cannot disagree.
func containerOf(dn string) (string, error) {
	return addn.Parent(dn)
}

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

// presenceCheck is what Test-AdPresence returns. The script never decides
// whether an object is gone: it hands the exception back so the classifier,
// which fails closed, makes the call.
type presenceCheck struct {
	Found     bool   `json:"found"`
	Type      string `json:"type"`
	ErrorCode int    `json:"errorCode"`
	Message   string `json:"message"`
}

// confirmAbsent turns a presence probe into the delete verdict. A destroy that
// silently no-ops is worse than one that fails: Terraform drops the resource
// from state and the object is then unmanaged and invisible.
func (p presenceCheck) confirmAbsent(op string, id Identity, dn string) error {
	if p.Found {
		return &Error{
			Kind: KindConstraint, Op: op, Identity: id.String(), Target: dn,
			Err: fmt.Errorf("the remove cmdlet returned cleanly but the object is still present; " +
				"the deletion was refused"),
		}
	}
	if kind := Classify(p.Type, p.ErrorCode); kind != KindNotFound {
		return &Error{
			Kind: kind, Op: op, Identity: id.String(), Target: dn,
			ExceptionType: p.Type, Code: p.ErrorCode, ServerMessage: p.Message,
			Err: fmt.Errorf("could not verify the deletion"),
		}
	}
	return nil
}

// withIdentity stamps the identity onto an error that came back from a script,
// so a diagnostic can name what was acted on.
func withIdentity(err error, op string, id Identity) error {
	var e *Error
	if asAdpwshError(err, &e) {
		if e.Op == "" {
			e.Op = op
		}
		if e.Identity == "" {
			e.Identity = id.String()
		}
		return e
	}
	return err
}

// GroupSpec is the desired state of a group.
type GroupSpec struct {
	Name           string // the CN; a change means Rename-ADObject
	SamAccountName string // required; changes through Set-ADGroup
	Container      string // parent DN; a change means Move-ADObject
	Scope          GroupScope
	Category       GroupCategory // defaults to security
	Description    *string
	ManagedBy      *string
}

func (s GroupSpec) validate(op string, forCreate bool) error {
	if err := validateName(op, s.Name); err != nil {
		return err
	}
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if err := validateContainer(op, s.Container); err != nil {
		return err
	}
	// -GroupScope is a mandatory parameter of New-ADGroup, so there is no
	// meaningful default to fall back on.
	if forCreate && s.Scope == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Scope is required (global, domainlocal or universal)")}
	}
	if s.Scope != "" {
		if _, ok := s.Scope.cmdletValue(); !ok {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Scope %q is not one of global, domainlocal, universal", s.Scope)}
		}
	}
	if s.Category != "" {
		if _, ok := s.Category.cmdletValue(); !ok {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Category %q is not one of security, distribution", s.Category)}
		}
	}
	return nil
}

// UserSpec is the desired state of a user account.
type UserSpec struct {
	SamAccountName    string  // required on create
	Container         string  // required on create; a change means Move-ADObject
	Name              *string // the CN; defaults to SamAccountName on create; a change means Rename-ADObject
	UserPrincipalName *string
	DisplayName       *string
	GivenName         *string
	Surname           *string
	Description       *string

	Enabled               *bool
	Password              *Secret
	ChangePasswordAtLogon *bool
	CanChangePassword     *bool
	PasswordExpires       *bool
	AccountExpiration     OptTime
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

func (s UserSpec) validate(op string) error {
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if err := validateContainer(op, s.Container); err != nil {
		return err
	}
	if s.AccountExpiration.IsSet() && s.AccountExpiration.IsClear() {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("AccountExpiration cannot both set and clear")}
	}
	// Correctness rule 7. AD accepts these combinations and then behaves in a
	// way nobody asked for, so they are refused before a round trip.
	if s.ChangePasswordAtLogon != nil && *s.ChangePasswordAtLogon {
		if s.PasswordExpires != nil && !*s.PasswordExpires {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf(
				"change_password_at_logon cannot be true while password_expires is false: " +
					"AD cannot require a change of a password that never expires")}
		}
		if s.CanChangePassword != nil && !*s.CanChangePassword {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf(
				"change_password_at_logon cannot be true while can_change_password is false: " +
					"the user would be required to do what they are denied")}
		}
	}
	return nil
}

// GMSASpec is the desired state of a group Managed Service Account. Pointer
// fields follow the tri-state convention: nil leaves the attribute alone, a
// pointer to "" clears it, a pointer to a value sets it.
type GMSASpec struct {
	Name                          string // CN; required
	SamAccountName                string // required; <= 15 chars, "$" is added by AD
	Container                     string // parent DN; required
	DNSHostName                   *string
	Description                   *string
	DisplayName                   *string
	Enabled                       *bool
	TrustedForDelegation          *bool
	PrincipalsAllowed             []Identity // full-replace; nil leaves alone, non-nil (incl. empty) replaces
	ServicePrincipalNames         *[]string  // nil leaves alone, non-nil (incl. empty) replaces
	KerberosEncryptionType        *[]string  // nil leaves alone, non-nil replaces
	AccountExpiration             OptTime
	ManagedPasswordIntervalInDays *int // create-only; ignored on Update
}

const gmsaSamMaxLen = 15

// forCreate follows the same convention GroupSpec.validate uses: the op
// string is for error stamping only, never for branching. Branching on it
// (as an earlier version of this method did, comparing op == "GMSA.Create")
// silently breaks the moment a caller's op string doesn't match that literal
// — which is exactly what happened here, since ServiceAccountClient.Create
// (following the <Resource>.<Verb> convention every other sub-client uses)
// passes "ServiceAccount.Create", not "GMSA.Create".
func (s GMSASpec) validate(op string, forCreate bool) error {
	if err := validateName(op, s.Name); err != nil {
		return err
	}
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if len(s.SamAccountName) > gmsaSamMaxLen {
		return &Error{Kind: KindConstraint, Op: op,
			Err: fmt.Errorf("SamAccountName %q is %d characters; a gMSA sAMAccountName must be at most %d", s.SamAccountName, len(s.SamAccountName), gmsaSamMaxLen)}
	}
	if err := validateContainer(op, s.Container); err != nil {
		return err
	}
	if forCreate && (s.DNSHostName == nil || *s.DNSHostName == "") {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("DNSHostName is required")}
	}
	return nil
}

// Int is the pointer helper for optional integers.
func Int(i int) *int { return &i }
