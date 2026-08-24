package adpwsh

import "time"

// computerProject is the explicit -Properties list requested on every read.
// Get-ADComputer returns almost nothing by default, and never "*".
var computerProject = []string{
	"ObjectGUID", "DistinguishedName", "Name", "SamAccountName", "SID", "Enabled",
	"DNSHostName", "Description", "DisplayName", "Location", "ManagedBy",
	"TrustedForDelegation", "ServicePrincipalName", "msDS-AllowedToDelegateTo",
	"PrincipalsAllowedToDelegateToAccount", "msDS-SupportedEncryptionTypes",
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
