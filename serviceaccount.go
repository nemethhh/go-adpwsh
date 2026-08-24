package adpwsh

import (
	"context"
	"fmt"
	"time"

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
