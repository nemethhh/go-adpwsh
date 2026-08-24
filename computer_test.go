package adpwsh

import "testing"

// TestComputerJSONModel exercises computerJSON.model() directly, mirroring
// the gmsaJSON.model() coverage in serviceaccount_test.go: it maps a
// representative DTO and checks the fields that need derivation (Container
// from the DN, AccountExpiration from the RFC3339Nano string) rather than a
// straight field copy.
func TestComputerJSONModel(t *testing.T) {
	j := computerJSON{
		ObjectGUID:             "11111111-1111-1111-1111-111111111111",
		DistinguishedName:      "CN=WEB01,OU=tfacc,DC=corp,DC=local",
		Name:                   "WEB01",
		SamAccountName:         "WEB01$",
		SID:                    "S-1-5-21-1-2-3-1000",
		Enabled:                true,
		DNSHostName:            "web01.corp.local",
		Description:            "front end",
		ServicePrincipalNames:  []string{"HOST/web01", "HOST/web01.corp.local"},
		PrincipalsAllowed:      []string{"22222222-2222-2222-2222-222222222222"},
		AllowedToDelegateTo:    []string{"HTTP/db01.corp.local"},
		KerberosEncryptionType: []string{"AES128", "AES256"},
		OperatingSystem:        "Windows Server 2025 Standard",
		OperatingSystemVersion: "10.0 (26100)",
		AccountExpirationDate:  "2027-01-02T03:04:05.0000000Z",
	}
	c, err := j.model()
	if err != nil {
		t.Fatalf("model(): %v", err)
	}
	if c.Container != "OU=tfacc,DC=corp,DC=local" {
		t.Errorf("Container=%q", c.Container)
	}
	if c.SamAccountName != "WEB01$" {
		t.Errorf("sam=%q (library keeps $, provider strips)", c.SamAccountName)
	}
	if c.AccountExpiration == nil || c.AccountExpiration.Year() != 2027 {
		t.Errorf("expiry=%v", c.AccountExpiration)
	}
	if c.OperatingSystem == "" {
		t.Errorf("OS not carried")
	}
}
