package adpwsh

import (
	"context"
	"fmt"
	"time"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// gmsaProject is what a gMSA read asks for. Get-ADServiceAccount does not
// return any of these by default, and never "*".
var gmsaProject = []string{
	"DNSHostName", "Description", "DisplayName", "Enabled", "TrustedForDelegation",
	"PrincipalsAllowedToRetrieveManagedPassword", "ServicePrincipalNames",
	"KerberosEncryptionType", "ManagedPasswordIntervalInDays", "AccountExpirationDate",
}

// ServiceAccountClient is the group Managed Service Account (gMSA) sub-client.
type ServiceAccountClient struct{ c *core }

type gmsaJSON struct {
	GUID                  string   `json:"objectGUID"`
	DN                    string   `json:"distinguishedName"`
	Name                  string   `json:"name"`
	SamAccountName        string   `json:"samAccountName"`
	SID                   string   `json:"sid"`
	DNSHostName           string   `json:"dnsHostName"`
	Description           string   `json:"description"`
	DisplayName           string   `json:"displayName"`
	Enabled               bool     `json:"enabled"`
	TrustedForDelegation  bool     `json:"trustedForDelegation"`
	PrincipalsAllowed     []string `json:"principalsAllowed"`
	ServicePrincipalNames []string `json:"servicePrincipalNames"`
	KerberosEncryption    []string `json:"kerberosEncryptionType"`
	IntervalDays          int      `json:"managedPasswordIntervalInDays"`
	AccountExpirationDate *string  `json:"accountExpirationDate"`
}

func (j gmsaJSON) model() (*GMSA, error) {
	container, err := containerOf(j.DN)
	if err != nil {
		return nil, err
	}
	g := &GMSA{
		GUID: j.GUID, DN: j.DN, Name: j.Name, SamAccountName: j.SamAccountName,
		Container: container, SID: j.SID, DNSHostName: j.DNSHostName,
		Description: j.Description, DisplayName: j.DisplayName, Enabled: j.Enabled,
		TrustedForDelegation: j.TrustedForDelegation, PrincipalsAllowed: j.PrincipalsAllowed,
		ServicePrincipalNames: j.ServicePrincipalNames, KerberosEncryptionType: j.KerberosEncryption,
		ManagedPasswordIntervalInDays: j.IntervalDays,
	}
	if j.AccountExpirationDate != nil && *j.AccountExpirationDate != "" {
		t, err := time.Parse(time.RFC3339Nano, *j.AccountExpirationDate)
		if err != nil {
			return nil, err
		}
		utc := t.UTC()
		g.AccountExpiration = &utc
	}
	return g, nil
}

// Create makes a group Managed Service Account and returns the result of the
// same read Get performs. It may return a non-nil GMSA together with a
// non-nil error on a replication timeout; the caller must persist the model
// and surface the error.
func (s *ServiceAccountClient) Create(ctx context.Context, spec GMSASpec) (*GMSA, error) {
	const op = "ServiceAccount.Create"
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
	if spec.Enabled != nil {
		create["Enabled"] = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil {
		create["TrustedForDelegation"] = *spec.TrustedForDelegation
	}
	// ServicePrincipalNames is a plain list on create; Set-ADServiceAccount's
	// {Add,Remove,Replace,Clear} hashtable form only applies on Update.
	if spec.ServicePrincipalNames != nil {
		create["ServicePrincipalNames"] = *spec.ServicePrincipalNames
	}
	if spec.PrincipalsAllowed != nil {
		create["PrincipalsAllowedToRetrieveManagedPassword"] = identityArgs(spec.PrincipalsAllowed)
	}
	if spec.KerberosEncryptionType != nil {
		create["KerberosEncryptionType"] = *spec.KerberosEncryptionType
	}
	if spec.AccountExpiration.IsSet() {
		create["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	}
	if spec.ManagedPasswordIntervalInDays != nil {
		create["ManagedPasswordIntervalInDays"] = *spec.ManagedPasswordIntervalInDays
	}

	var out gmsaJSON
	if err := s.c.exec(ctx, adscript.OpGMSACreate, map[string]any{
		"create": create, "project": gmsaProject,
	}, &out); err != nil {
		return nil, s.c.annotateAlreadyExists(ctx, err, deletedPrincipalFilter(spec.SamAccountName))
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, s.c.replicate(ctx, model.GUID)
}

// Get reads one group Managed Service Account.
func (s *ServiceAccountClient) Get(ctx context.Context, id Identity) (*GMSA, error) {
	var out gmsaJSON
	if err := s.c.exec(ctx, adscript.OpGMSARead, map[string]any{
		"identity": id.identityArg(), "project": gmsaProject,
	}, &out); err != nil {
		return nil, withIdentity(err, "ServiceAccount.Get", id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: "ServiceAccount.Get", Err: err}
	}
	return model, nil
}

// Search returns every group Managed Service Account under q.SearchBase
// matching q.Filter.
func (s *ServiceAccountClient) Search(ctx context.Context, q Query) ([]GMSA, error) {
	const op = "ServiceAccount.Search"
	q = q.withDefaults(s.c.dnc)
	var out struct {
		Results []gmsaJSON `json:"results"`
	}
	if err := s.c.exec(ctx, adscript.OpGMSASearch, q.payload(gmsaProject), &out); err != nil {
		return nil, err
	}
	if len(out.Results) > q.SizeLimit {
		return nil, &Error{Kind: KindTooManyResults, Op: op,
			Err: fmt.Errorf("more than %d objects matched; narrow the filter or raise the limit", q.SizeLimit)}
	}
	models := make([]GMSA, 0, len(out.Results))
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
// trip. ManagedPasswordIntervalInDays is never referenced here: it is
// create-only, since Set-ADServiceAccount has no such parameter.
func (s *ServiceAccountClient) Update(ctx context.Context, id Identity, spec GMSASpec) (*GMSA, error) {
	const op = "ServiceAccount.Update"
	if err := spec.validate(op, false); err != nil {
		return nil, err
	}

	unlock := s.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"identity": id.identityArg(), "project": gmsaProject}

	var ops adscript.AttrOps
	set := map[string]any{"Identity": id.identityArg()}
	applyStringField(&ops, set, "DNSHostName", "dNSHostName", spec.DNSHostName)
	applyStringField(&ops, set, "Description", "description", spec.Description)
	applyStringField(&ops, set, "DisplayName", "displayName", spec.DisplayName)
	if spec.Enabled != nil && *spec.Enabled != current.Enabled {
		set["Enabled"] = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil && *spec.TrustedForDelegation != current.TrustedForDelegation {
		set["TrustedForDelegation"] = *spec.TrustedForDelegation
	}
	// PrincipalsAllowed, ServicePrincipalNames and KerberosEncryptionType are
	// full-replace, not diffed against current: a nil pointer/slice leaves the
	// attribute alone, and any non-nil value (including an empty one) replaces
	// it wholesale.
	if spec.PrincipalsAllowed != nil {
		set["PrincipalsAllowedToRetrieveManagedPassword"] = identityArgs(spec.PrincipalsAllowed)
	}
	if spec.ServicePrincipalNames != nil {
		// Set-ADServiceAccount only accepts the {Add,Remove,Replace,Clear}
		// hashtable form for ServicePrincipalNames; a plain list, which
		// New-ADServiceAccount accepts, fails on a real DC.
		set["ServicePrincipalNames"] = map[string]any{"Replace": *spec.ServicePrincipalNames}
	}
	if spec.KerberosEncryptionType != nil {
		set["KerberosEncryptionType"] = *spec.KerberosEncryptionType
	}
	switch {
	case spec.AccountExpiration.IsSet():
		set["AccountExpirationDate"] = spec.AccountExpiration.Value().UTC().Format(time.RFC3339)
	case spec.AccountExpiration.IsClear():
		// Same reasoning as User.Update: accountExpires is a system attribute
		// that is always present (its "never" value is 0x7FFFFFFFFFFFFFFF), so
		// "never expires" is Set-ADServiceAccount -AccountExpirationDate $null,
		// not -Clear accountExpires, which a real DC refuses as an illegal
		// modify.
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

	var out gmsaJSON
	if err := s.c.exec(ctx, adscript.OpGMSAUpdate, payload, &out); err != nil {
		return nil, withIdentity(err, op, id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, s.c.replicate(ctx, model.GUID)
}

// Delete removes a group Managed Service Account and returns nil only after a
// re-read confirms it is gone.
func (s *ServiceAccountClient) Delete(ctx context.Context, id Identity) error {
	const op = "ServiceAccount.Delete"

	unlock := s.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	var out struct {
		Deleted bool          `json:"deleted"`
		Verify  presenceCheck `json:"verify"`
	}
	if err := s.c.exec(ctx, adscript.OpGMSADelete, map[string]any{"identity": current.GUID}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	return out.Verify.confirmAbsent(op, id, current.DN)
}
