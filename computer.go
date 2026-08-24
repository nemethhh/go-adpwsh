package adpwsh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// computerProject is the explicit -Properties list requested on every read.
// Get-ADComputer returns almost nothing by default, and never "*". The SPN
// and Kerberos encryption entries request the friendly, decoded property
// names (ServicePrincipalNames, KerberosEncryptionType) — the same ones
// gmsaProject requests — not the raw LDAP attribute names
// (ServicePrincipalName singular; msDS-SupportedEncryptionTypes, an
// undecoded bitmask). Requesting the raw names leaves the friendly
// properties Convert-AdComputer reads unpopulated, or populated with a raw
// integer instead of a decoded flag list.
var computerProject = []string{
	"ObjectGUID", "DistinguishedName", "Name", "SamAccountName", "SID", "Enabled",
	"DNSHostName", "Description", "DisplayName", "Location", "ManagedBy",
	"TrustedForDelegation", "ServicePrincipalNames", "msDS-AllowedToDelegateTo",
	"PrincipalsAllowedToDelegateToAccount", "KerberosEncryptionType",
	"AccountExpirationDate", "OperatingSystem", "OperatingSystemVersion",
	"OperatingSystemServicePack",
}

// computerJSON is the DTO Convert-AdComputer (Task 1.3) emits. The json tags
// are a cross-task contract with that PowerShell function and must match its
// emitted property names exactly.
type computerJSON struct {
	ObjectGUID                 string   `json:"ObjectGUID"`
	DistinguishedName          string   `json:"DistinguishedName"`
	Name                       string   `json:"Name"`
	SamAccountName             string   `json:"SamAccountName"`
	SID                        string   `json:"SID"`
	Enabled                    bool     `json:"Enabled"`
	DNSHostName                string   `json:"DNSHostName"`
	Description                string   `json:"Description"`
	DisplayName                string   `json:"DisplayName"`
	Location                   string   `json:"Location"`
	ManagedBy                  string   `json:"ManagedBy"`
	TrustedForDelegation       bool     `json:"TrustedForDelegation"`
	ServicePrincipalNames      []string `json:"ServicePrincipalNames"`
	AllowedToDelegateTo        []string `json:"AllowedToDelegateTo"`
	PrincipalsAllowed          []string `json:"PrincipalsAllowed"`
	KerberosEncryptionType     []string `json:"KerberosEncryptionType"`
	AccountExpirationDate      string   `json:"AccountExpirationDate"`
	OperatingSystem            string   `json:"OperatingSystem"`
	OperatingSystemVersion     string   `json:"OperatingSystemVersion"`
	OperatingSystemServicePack string   `json:"OperatingSystemServicePack"`
}

func (j computerJSON) model() (*Computer, error) {
	container, err := containerOf(j.DistinguishedName)
	if err != nil {
		return nil, err
	}
	c := &Computer{
		GUID: j.ObjectGUID, DN: j.DistinguishedName, Name: j.Name,
		SamAccountName: j.SamAccountName, Container: container, SID: j.SID, Enabled: j.Enabled,
		DNSHostName: j.DNSHostName, Description: j.Description, DisplayName: j.DisplayName,
		Location: j.Location, ManagedBy: j.ManagedBy,
		TrustedForDelegation:  j.TrustedForDelegation,
		ServicePrincipalNames: j.ServicePrincipalNames, AllowedToDelegateTo: j.AllowedToDelegateTo,
		PrincipalsAllowed: j.PrincipalsAllowed, KerberosEncryptionType: j.KerberosEncryptionType,
		OperatingSystem: j.OperatingSystem, OperatingSystemVersion: j.OperatingSystemVersion,
		OperatingSystemServicePack: j.OperatingSystemServicePack,
	}
	if j.AccountExpirationDate != "" {
		t, err := time.Parse(time.RFC3339Nano, j.AccountExpirationDate)
		if err != nil {
			return nil, err
		}
		utc := t.UTC()
		c.AccountExpiration = &utc
	}
	return c, nil
}

// ComputerClient is the computer account (objectClass "computer") sub-client.
type ComputerClient struct{ c *core }

// Create makes a computer account and returns the result of the same read Get
// performs. It may return a non-nil Computer together with a non-nil error on
// a replication timeout; the caller must persist the model and surface the
// error. OperatingSystem/OperatingSystemVersion/OperatingSystemServicePack are
// never written here: they are read-only (the joined machine owns them) and
// are not on ComputerSpec.
func (cc *ComputerClient) Create(ctx context.Context, spec ComputerSpec) (*Computer, error) {
	const op = "Computer.Create"
	if err := spec.validate(op, true); err != nil {
		return nil, err
	}

	create := map[string]any{
		"Name":           spec.Name,
		"SamAccountName": spec.SamAccountName,
		"Path":           spec.Container,
	}
	if spec.DNSHostName != nil && *spec.DNSHostName != "" {
		create["DNSHostName"] = *spec.DNSHostName
	}
	if spec.Description != nil && *spec.Description != "" {
		create["Description"] = *spec.Description
	}
	if spec.DisplayName != nil && *spec.DisplayName != "" {
		create["DisplayName"] = *spec.DisplayName
	}
	if spec.Location != nil && *spec.Location != "" {
		create["Location"] = *spec.Location
	}
	if spec.ManagedBy != nil && *spec.ManagedBy != "" {
		create["ManagedBy"] = *spec.ManagedBy
	}
	if spec.Enabled != nil {
		create["Enabled"] = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil {
		create["TrustedForDelegation"] = *spec.TrustedForDelegation
	}
	// ServicePrincipalNames is a plain list on create; the
	// {Add,Remove,Replace,Clear} hashtable form Update uses only applies to
	// Set-ADComputer, mirroring the ServicePrincipalNames precedent in
	// ServiceAccountClient.Create.
	if spec.ServicePrincipalNames != nil {
		create["ServicePrincipalNames"] = *spec.ServicePrincipalNames
	}
	// msDS-AllowedToDelegateTo (classic constrained delegation) has no
	// friendly New-ADComputer parameter, unlike ServicePrincipalNames: a
	// lab run against a real DC confirmed New-ADComputer rejects
	// -AllowedToDelegateTo outright ("A parameter cannot be found that
	// matches parameter name 'AllowedToDelegateTo'"). A non-empty value
	// rides in -OtherAttributes under its raw LDAP name instead; nil or
	// empty is simply omitted, since there is nothing to clear on a brand
	// new object.
	if spec.AllowedToDelegateTo != nil && len(*spec.AllowedToDelegateTo) > 0 {
		create["OtherAttributes"] = map[string]any{"msDS-AllowedToDelegateTo": *spec.AllowedToDelegateTo}
	}
	if spec.PrincipalsAllowed != nil {
		create["PrincipalsAllowedToDelegateToAccount"] = identityArgs(spec.PrincipalsAllowed)
	}
	if spec.KerberosEncryptionType != nil {
		create["KerberosEncryptionType"] = *spec.KerberosEncryptionType
	}
	if spec.AccountExpiration.IsSet() {
		create["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	}

	var out computerJSON
	if err := cc.c.exec(ctx, adscript.OpComputerCreate, map[string]any{
		"create": create, "project": computerProject,
	}, &out); err != nil {
		return nil, cc.c.annotateAlreadyExists(ctx, err, deletedPrincipalFilter(spec.SamAccountName))
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, cc.c.replicate(ctx, model.GUID)
}

// Get reads one computer account.
func (cc *ComputerClient) Get(ctx context.Context, id Identity) (*Computer, error) {
	var out computerJSON
	if err := cc.c.exec(ctx, adscript.OpComputerRead, map[string]any{
		"identity": id.identityArg(), "project": computerProject,
	}, &out); err != nil {
		return nil, withIdentity(err, "Computer.Get", id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: "Computer.Get", Err: err}
	}
	return model, nil
}

// Search returns every computer account under q.SearchBase matching q.Filter.
func (cc *ComputerClient) Search(ctx context.Context, q Query) ([]Computer, error) {
	const op = "Computer.Search"
	q = q.withDefaults(cc.c.dnc)
	var out struct {
		Results []computerJSON `json:"results"`
	}
	if err := cc.c.exec(ctx, adscript.OpComputerSearch, q.payload(computerProject), &out); err != nil {
		return nil, err
	}
	if len(out.Results) > q.SizeLimit {
		return nil, &Error{Kind: KindTooManyResults, Op: op,
			Err: fmt.Errorf("more than %d objects matched; narrow the filter or raise the limit", q.SizeLimit)}
	}
	models := make([]Computer, 0, len(out.Results))
	for _, j := range out.Results {
		m, err := j.model()
		if err != nil {
			return nil, &Error{Kind: KindTransport, Op: op, Err: err}
		}
		models = append(models, *m)
	}
	return models, nil
}

// Update folds the attribute write, the rename and the move into one round
// trip.
func (cc *ComputerClient) Update(ctx context.Context, id Identity, spec ComputerSpec) (*Computer, error) {
	const op = "Computer.Update"
	if err := spec.validate(op, false); err != nil {
		return nil, err
	}

	unlock := cc.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := cc.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"identity": id.identityArg(), "project": computerProject}

	var ops adscript.AttrOps
	set := map[string]any{"Identity": id.identityArg()}
	applyStringField(&ops, set, "DNSHostName", "dNSHostName", spec.DNSHostName)
	applyStringField(&ops, set, "Description", "description", spec.Description)
	applyStringField(&ops, set, "DisplayName", "displayName", spec.DisplayName)
	applyStringField(&ops, set, "Location", "location", spec.Location)
	applyStringField(&ops, set, "ManagedBy", "managedBy", spec.ManagedBy)
	// AD appends "$" to a computer's sAMAccountName (see Create/the fake's
	// handleCreate), so current.SamAccountName is already suffixed while
	// spec.SamAccountName, the config value, never is. Comparing the two
	// directly would be always-true and churn -SamAccountName on every
	// update; strip the suffix current carries before diffing.
	if spec.SamAccountName != strings.TrimSuffix(current.SamAccountName, "$") {
		set["SamAccountName"] = spec.SamAccountName
	}
	if spec.Enabled != nil && *spec.Enabled != current.Enabled {
		set["Enabled"] = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil && *spec.TrustedForDelegation != current.TrustedForDelegation {
		set["TrustedForDelegation"] = *spec.TrustedForDelegation
	}
	// ServicePrincipalNames, AllowedToDelegateTo, PrincipalsAllowed and
	// KerberosEncryptionType are full-replace, not diffed against current: a
	// nil pointer/slice leaves the attribute alone, and any non-nil value
	// (including an empty one) replaces it wholesale — an empty replace is how
	// the attribute is cleared.
	if spec.ServicePrincipalNames != nil {
		// Set-ADComputer only accepts the {Add,Remove,Replace,Clear} hashtable
		// form for ServicePrincipalNames; a plain list, which New-ADComputer
		// accepts, fails on a real DC.
		set["ServicePrincipalNames"] = map[string]any{"Replace": *spec.ServicePrincipalNames}
	}
	// msDS-AllowedToDelegateTo has no friendly Set-ADComputer parameter either
	// (lab-verified: -AllowedToDelegateTo does not exist there any more than
	// on New-ADComputer). It is written through the raw LDAP name via the
	// same generic -Replace/-Clear mechanism the tri-state string fields
	// above already feed into ops, rather than a bespoke set["Replace"]/
	// set["Clear"] key: folding it into ops means a simultaneous string-field
	// -Clear in the same call (e.g. Description) merges into one -Clear list
	// instead of one silently clobbering the other.
	if spec.AllowedToDelegateTo != nil {
		if len(*spec.AllowedToDelegateTo) == 0 {
			ops.ClearName("msDS-AllowedToDelegateTo")
		} else {
			ops.ReplaceValue("msDS-AllowedToDelegateTo", *spec.AllowedToDelegateTo)
		}
	}
	if spec.PrincipalsAllowed != nil {
		set["PrincipalsAllowedToDelegateToAccount"] = identityArgs(spec.PrincipalsAllowed)
	}
	if spec.KerberosEncryptionType != nil {
		set["KerberosEncryptionType"] = *spec.KerberosEncryptionType
	}
	switch {
	case spec.AccountExpiration.IsSet():
		set["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	case spec.AccountExpiration.IsClear():
		// Same reasoning as User.Update/ServiceAccount.Update: accountExpires
		// is a system attribute that is always present (its "never" value is
		// 0x7FFFFFFFFFFFFFFF), so "never expires" is
		// Set-ADComputer -AccountExpirationDate $null, not -Clear
		// accountExpires, which a real DC refuses as an illegal modify.
		set["AccountExpirationDate"] = nil
	}
	if err := conflictToError(op, ops.Apply(set)); err != nil {
		return nil, err
	}
	if len(set) > 1 {
		payload["set"] = set
	}

	if spec.Name != current.Name {
		payload["rename"] = map[string]any{"Identity": id.identityArg(), "NewName": spec.Name}
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

	var out computerJSON
	if err := cc.c.exec(ctx, adscript.OpComputerUpdate, payload, &out); err != nil {
		return nil, withIdentity(err, op, id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, cc.c.replicate(ctx, model.GUID)
}

// Delete removes a computer account and returns nil only after a re-read
// confirms it is gone.
func (cc *ComputerClient) Delete(ctx context.Context, id Identity) error {
	const op = "Computer.Delete"

	unlock := cc.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := cc.Get(ctx, id)
	if err != nil {
		return err
	}
	var out struct {
		Deleted bool          `json:"deleted"`
		Verify  presenceCheck `json:"verify"`
	}
	if err := cc.c.exec(ctx, adscript.OpComputerDelete, map[string]any{"identity": current.GUID}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	return out.Verify.confirmAbsent(op, id, current.DN)
}
