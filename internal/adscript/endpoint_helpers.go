package adscript

// ACLEndpointHelpers returns the PowerShell -FunctionDefinitions array literal a
// ConstrainedLanguage endpoint must install for ACL delegation to work in
// constrained mode. It is the single source of truth; the provider's endpoint
// generator embeds a verbatim copy, guarded by a drift test.
func ACLEndpointHelpers() string {
	b, err := files.ReadFile("endpoint/acl_helpers.ps1")
	if err != nil {
		panic("adscript: embedded endpoint/acl_helpers.ps1 missing: " + err.Error())
	}
	return string(b)
}
