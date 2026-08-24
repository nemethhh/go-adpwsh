package adpwsh

import "testing"

func TestGMSASpecValidate(t *testing.T) {
	cases := []struct {
		name    string
		spec    GMSASpec
		wantErr bool
	}{
		{"ok", GMSASpec{Name: "svc-web", SamAccountName: "svc-web", Container: "OU=x,DC=corp,DC=local", DNSHostName: String("svc-web.corp.local")}, false},
		{"sam 15 ok", GMSASpec{Name: "abcdefghij12345", SamAccountName: "abcdefghij12345", Container: "OU=x,DC=corp,DC=local", DNSHostName: String("h.corp.local")}, false},
		{"sam 16 too long", GMSASpec{Name: "abcdefghij123456", SamAccountName: "abcdefghij123456", Container: "OU=x,DC=corp,DC=local", DNSHostName: String("h.corp.local")}, true},
		{"no container", GMSASpec{Name: "svc", SamAccountName: "svc", DNSHostName: String("h.corp.local")}, true},
		{"no dnshostname", GMSASpec{Name: "svc", SamAccountName: "svc", Container: "OU=x,DC=corp,DC=local"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.spec.validate("GMSA.Create")
			if (err != nil) != c.wantErr {
				t.Fatalf("validate() err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}
