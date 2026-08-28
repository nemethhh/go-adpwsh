package adpwsh

import "github.com/nemethhh/go-adpwsh/internal/adscript"

// ACLEndpointHelpers returns the PowerShell -FunctionDefinitions block that a
// ConstrainedLanguage management-host endpoint must install so the provider can
// run ACL delegation in constrained mode. The Terraform provider embeds a copy
// in its endpoint-registration script and drift-tests it against this value.
func ACLEndpointHelpers() string { return adscript.ACLEndpointHelpers() }
