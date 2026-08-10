package adpwsh

import "testing"

func TestIdentityConstructors(t *testing.T) {
	tests := []struct {
		name     string
		id       Identity
		wantArg  string
		wantForm string
	}{
		{"guid", ByGUID("9f2c8f1e-0000-0000-0000-000000000001"), "9f2c8f1e-0000-0000-0000-000000000001", "guid"},
		{"dn", ByDN("CN=jdoe,OU=Staff,DC=corp,DC=local"), "CN=jdoe,OU=Staff,DC=corp,DC=local", "dn"},
		{"sid", BySID("S-1-5-21-1-2-3-1104"), "S-1-5-21-1-2-3-1104", "sid"},
		{"sam", BySAM("jdoe"), "jdoe", "sam"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.identityArg(); got != tt.wantArg {
				t.Errorf("identityArg() = %q, want %q", got, tt.wantArg)
			}
			if got := tt.id.identityForm(); got != tt.wantForm {
				t.Errorf("identityForm() = %q, want %q", got, tt.wantForm)
			}
		})
	}
}

// The form is carried so diagnostics can say which identity space a failed
// lookup used, rather than printing a bare string.
func TestIdentityString(t *testing.T) {
	if got := BySAM("jdoe").String(); got != "sam:jdoe" {
		t.Errorf("String() = %q, want %q", got, "sam:jdoe")
	}
}
