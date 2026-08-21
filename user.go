package adpwsh

import (
	"context"
	"time"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// userProject is what a user read asks for. It names the extended properties
// the tier-1 flags read back through and the constructed attribute they derive
// from — none of which Get-ADUser returns by default — and never "*".
var userProject = []string{
	"Description", "DisplayName", "GivenName", "Surname", "UserPrincipalName",
	"Enabled", "CannotChangePassword", "PasswordNeverExpires", "pwdLastSet",
	"AccountExpirationDate", "msDS-User-Account-Control-Computed",
}

// UserClient is the user sub-client.
type UserClient struct{ c *core }

type userJSON struct {
	GUID                  string  `json:"objectGUID"`
	DN                    string  `json:"distinguishedName"`
	Name                  string  `json:"name"`
	SamAccountName        string  `json:"samAccountName"`
	UserPrincipalName     string  `json:"userPrincipalName"`
	DisplayName           string  `json:"displayName"`
	GivenName             string  `json:"givenName"`
	Surname               string  `json:"surname"`
	Description           string  `json:"description"`
	Enabled               bool    `json:"enabled"`
	SID                   string  `json:"sid"`
	ChangePasswordAtLogon bool    `json:"changePasswordAtLogon"`
	CanChangePassword     bool    `json:"canChangePassword"`
	PasswordExpires       bool    `json:"passwordExpires"`
	AccountExpirationDate *string `json:"accountExpirationDate"`
}

func (j userJSON) model() (*User, error) {
	container, err := containerOf(j.DN)
	if err != nil {
		return nil, err
	}
	u := &User{
		GUID: j.GUID, DN: j.DN, Name: j.Name, SamAccountName: j.SamAccountName,
		UserPrincipalName: j.UserPrincipalName, DisplayName: j.DisplayName,
		GivenName: j.GivenName, Surname: j.Surname, Description: j.Description,
		Container: container, Enabled: j.Enabled, SID: j.SID,
		ChangePasswordAtLogon: j.ChangePasswordAtLogon,
		CanChangePassword:     j.CanChangePassword,
		PasswordExpires:       j.PasswordExpires,
	}
	if j.AccountExpirationDate != nil && *j.AccountExpirationDate != "" {
		t, err := time.Parse(time.RFC3339Nano, *j.AccountExpirationDate)
		if err != nil {
			return nil, err
		}
		utc := t.UTC()
		u.AccountExpiration = &utc
	}
	return u, nil
}

// Create makes a user account and returns the result of the same read Get
// performs. It may return a non-nil User together with a non-nil error on a
// replication timeout; the caller must persist the model and surface the error.
//
// AD refuses to enable an account with no password satisfying domain policy,
// so Enabled: true without a Password fails with AD's own error rather than
// being papered over by silently creating a disabled account.
func (u *UserClient) Create(ctx context.Context, spec UserSpec) (*User, error) {
	const op = "User.Create"
	if err := spec.validate(op); err != nil {
		return nil, err
	}

	name := spec.SamAccountName
	if spec.Name != nil && *spec.Name != "" {
		name = *spec.Name
	}
	create := map[string]any{
		"Name":           name,
		"SamAccountName": spec.SamAccountName,
		"Path":           spec.Container,
	}
	for _, f := range userTier1 {
		if v := f.Get(spec); v != nil && *v != "" {
			create[f.Param] = *v
		}
	}
	if spec.Enabled != nil {
		create["Enabled"] = *spec.Enabled
	}
	if spec.ChangePasswordAtLogon != nil {
		create["ChangePasswordAtLogon"] = *spec.ChangePasswordAtLogon
	}
	if spec.CanChangePassword != nil {
		create["CannotChangePassword"] = !*spec.CanChangePassword
	}
	if spec.PasswordExpires != nil {
		create["PasswordNeverExpires"] = !*spec.PasswordExpires
	}
	if spec.AccountExpiration.IsSet() {
		create["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	}

	payload := map[string]any{"create": create, "project": userProject}
	if spec.Password != nil && !spec.Password.IsZero() {
		// The plaintext rides beside the splat; the script turns it into a
		// SecureString. A Secret in the splat would fail to marshal, loudly.
		payload["password"] = spec.Password.reveal()
	}

	var out userJSON
	if err := u.c.exec(ctx, adscript.OpUserCreate, payload, &out); err != nil {
		return nil, u.c.annotateAlreadyExists(ctx, err, deletedPrincipalFilter(spec.SamAccountName))
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, u.c.replicate(ctx, model.GUID)
}

// Get reads one user.
func (u *UserClient) Get(ctx context.Context, id Identity) (*User, error) {
	var out userJSON
	if err := u.c.exec(ctx, adscript.OpUserRead, map[string]any{
		"identity": id.identityArg(), "project": userProject,
	}, &out); err != nil {
		return nil, withIdentity(err, "User.Get", id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: "User.Get", Err: err}
	}
	return model, nil
}

// Update folds the attribute write, the rename and the move into one round
// trip. It never changes the password: -AccountPassword does not exist on
// Set-ADUser, so rotation goes through SetPassword.
func (u *UserClient) Update(ctx context.Context, id Identity, spec UserSpec) (*User, error) {
	const op = "User.Update"
	if err := spec.validate(op); err != nil {
		return nil, err
	}

	unlock := u.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := u.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"identity": id.identityArg(), "project": userProject}

	var ops adscript.AttrOps
	set := map[string]any{"Identity": id.identityArg()}
	for _, f := range userTier1 {
		applyStringField(&ops, set, f.Param, f.LDAP, f.Get(spec))
	}
	if spec.SamAccountName != current.SamAccountName {
		set["SamAccountName"] = spec.SamAccountName
	}
	if spec.Enabled != nil && *spec.Enabled != current.Enabled {
		set["Enabled"] = *spec.Enabled
	}
	if spec.ChangePasswordAtLogon != nil && *spec.ChangePasswordAtLogon != current.ChangePasswordAtLogon {
		set["ChangePasswordAtLogon"] = *spec.ChangePasswordAtLogon
	}
	if spec.CanChangePassword != nil && *spec.CanChangePassword != current.CanChangePassword {
		set["CannotChangePassword"] = !*spec.CanChangePassword
	}
	if spec.PasswordExpires != nil && *spec.PasswordExpires != current.PasswordExpires {
		set["PasswordNeverExpires"] = !*spec.PasswordExpires
	}
	switch {
	case spec.AccountExpiration.IsSet():
		set["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	case spec.AccountExpiration.IsClear():
		// "Never expires" is Set-ADUser -AccountExpirationDate $null, not
		// -Clear accountExpires. accountExpires is a system attribute that is
		// always present (its "never" value is 0x7FFFFFFFFFFFFFFF), so removing
		// it is an illegal modify that a real DC rejects with
		// ADIllegalModifyOperationException. A Go nil in the splat map marshals
		// to JSON null, which the cmdlet receives as $null.
		set["AccountExpirationDate"] = nil
	}
	if err := conflictToError(op, ops.Apply(set)); err != nil {
		return nil, err
	}
	if len(set) > 1 {
		payload["set"] = set
	}

	if spec.Name != nil && *spec.Name != "" && *spec.Name != current.Name {
		payload["rename"] = map[string]any{"Identity": id.identityArg(), "NewName": *spec.Name}
	}
	sameContainer, err := addn.EqualFold(spec.Container, current.Container)
	if err != nil {
		return nil, &Error{Kind: KindConstraint, Op: op, Err: err}
	}
	if !sameContainer {
		payload["move"] = map[string]any{"Identity": id.identityArg(), "TargetPath": spec.Container}
	}

	if payload["set"] == nil && payload["rename"] == nil && payload["move"] == nil {
		return current, nil
	}

	var out userJSON
	if err := u.c.exec(ctx, adscript.OpUserUpdate, payload, &out); err != nil {
		return nil, withIdentity(err, op, id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, u.c.replicate(ctx, model.GUID)
}

// SetPassword resets the account's password through
// Set-ADAccountPassword -Reset. The error it returns never echoes the value.
func (u *UserClient) SetPassword(ctx context.Context, id Identity, pw Secret) error {
	const op = "User.SetPassword"
	if pw.IsZero() {
		return &Error{Kind: KindPassword, Op: op, Identity: id.String(), Err: errEmptyPassword}
	}

	unlock := u.c.locks.lock(id.identityArg())
	defer unlock()

	var out struct {
		Reset bool `json:"reset"`
	}
	if err := u.c.exec(ctx, adscript.OpUserSetPassword, map[string]any{
		"identity": id.identityArg(),
		"password": pw.reveal(),
	}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	return nil
}

// Delete removes a user and returns nil only after a re-read confirms it is
// gone.
func (u *UserClient) Delete(ctx context.Context, id Identity) error {
	const op = "User.Delete"

	unlock := u.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := u.Get(ctx, id)
	if err != nil {
		return err
	}
	var out struct {
		Deleted bool          `json:"deleted"`
		Verify  presenceCheck `json:"verify"`
	}
	if err := u.c.exec(ctx, adscript.OpUserDelete, map[string]any{"identity": current.GUID}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	return out.Verify.confirmAbsent(op, id, current.DN)
}
