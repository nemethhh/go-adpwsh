package adscript

import (
	"strings"
	"testing"
)

func TestACLEndpointHelpersContent(t *testing.T) {
	s := ACLEndpointHelpers()
	for _, want := range []string{"Set-AdAce", "Get-AdAce", "Remove-AdAce", "ActiveDirectoryAccessRule", "New-PSDrive"} {
		if !strings.Contains(s, want) {
			t.Errorf("ACL endpoint helpers missing %q", want)
		}
	}
}
