package adscript

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden script files")

// The script text is constant, so golden files diff cleanly and any change to
// what actually runs on the jump box is a reviewable diff.
func TestScriptGolden(t *testing.T) {
	for _, op := range Ops() {
		t.Run(op, func(t *testing.T) {
			got, err := Script(op)
			if err != nil {
				t.Fatalf("Script(%q): %v", op, err)
			}
			path := filepath.Join("testdata", "golden", op+".ps1")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run: go test ./internal/adscript -run TestScriptGolden -update)", err)
			}
			if got != string(want) {
				t.Errorf("script for %q changed; diff %s against the new output", op, path)
			}
		})
	}
}

func TestScriptInvariants(t *testing.T) {
	for _, op := range Ops() {
		s, err := Script(op)
		if err != nil {
			t.Fatalf("Script(%q): %v", op, err)
		}
		for _, want := range []string{
			"$ErrorActionPreference = 'Stop'",
			"Import-Module ActiveDirectory -ErrorAction Stop",
			"ConvertTo-AdHashtable ($__adRaw | ConvertFrom-Json)",
			"<<<TFAD:BEGIN>>>",
			"<<<TFAD:END>>>",
			"-Depth 6 -Compress",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("op %q: composed script is missing %q", op, want)
			}
		}
	}
}

func TestScriptComposesMembershipOps(t *testing.T) {
	cases := map[string]string{
		OpGroupMembersRead:          "-Properties member",
		OpGroupMembersReadRecursive: "-Recursive",
		OpGroupMembersAdd:           "Add-ADGroupMember",
		OpGroupMembersRemove:        "Remove-ADGroupMember",
		OpGroupMemberCheck:          "Test-AdMember",
	}
	for op, want := range cases {
		s, err := Script(op)
		if err != nil {
			t.Fatalf("Script(%q): %v", op, err)
		}
		if !strings.Contains(s, want) {
			t.Errorf("Script(%q) does not contain %q", op, want)
		}
		if !strings.Contains(s, "Import-Module ActiveDirectory") {
			t.Errorf("Script(%q) is missing the preamble", op)
		}
	}
	// The LDAP ";range=" attribute option is rejected by Get-ADObject
	// (System.ArgumentException on a real domain); the cmdlets page a
	// multivalued attribute internally, so the read must never use it.
	read, err := Script(OpGroupMembersRead)
	if err != nil {
		t.Fatalf("Script(%q): %v", OpGroupMembersRead, err)
	}
	if strings.Contains(read, "range=") {
		t.Errorf("Script(%q) uses the ranged-retrieval attribute option, which the cmdlets reject", OpGroupMembersRead)
	}
}

// Script takes an op name from a closed set, which is what makes formatting a
// value into script text impossible rather than merely discouraged.
func TestScriptRejectsUnknownOp(t *testing.T) {
	if _, err := Script("rm -rf /"); err == nil {
		t.Fatal("Script must reject an unknown op")
	}
}

func TestScriptIsStable(t *testing.T) {
	a, _ := Script(OpUserCreate)
	b, _ := Script(OpUserCreate)
	if a != b {
		t.Error("Script must return identical text on every call")
	}
}

// The tool set is separate from the op set on purpose. A schema export is
// build-time tooling — nothing in an apply path queries the schema — so it does
// not earn a place among the operations the library performs, and no caller of
// Script can reach it.
func TestToolsAreNotOps(t *testing.T) {
	for _, tool := range Tools() {
		if _, err := Script(tool); err == nil {
			t.Errorf("Script(%q) must fail: tools are not ops", tool)
		}
	}
	for _, op := range Ops() {
		if _, err := ToolScript(op); err == nil {
			t.Errorf("ToolScript(%q) must fail: ops are not tools", op)
		}
	}
	if _, err := ToolScript("rm -rf /"); err == nil {
		t.Fatal("ToolScript must reject an unknown name")
	}
}

// The tool script is constant, so it diffs cleanly exactly as the ops do.
func TestToolScriptGolden(t *testing.T) {
	for _, tool := range Tools() {
		t.Run(tool, func(t *testing.T) {
			got, err := ToolScript(tool)
			if err != nil {
				t.Fatalf("ToolScript(%q): %v", tool, err)
			}
			path := filepath.Join("testdata", "golden", "tools", tool+".ps1")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run: go test ./internal/adscript -run TestToolScriptGolden -update)", err)
			}
			if got != string(want) {
				t.Errorf("script for %q changed; diff %s against the new output", tool, path)
			}
		})
	}
}

// TestSchemaFetchArraysSurviveASingleElement pins the fix for a real defect: a
// class whose auxiliaryClass/mayContain/mustContain (or their system- twins)
// has exactly one value used to reach the JSON output as a bare string, not a
// one-element array, because PowerShell's function-return output stream
// unwraps a single-element array — Convert-AdSchemaNames's own internal @()
// does not survive being returned. The fix re-wraps each call site in @() at
// the point the JSON object is built, exactly like the attributes/classes
// arrays a few lines above it.
//
// No PowerShell runs in CI, so a shape assertion on the composed script text
// is the only guard available here: it cannot prove the JSON comes out right,
// only that the six call sites keep the @() that makes it so. The lab run
// against a real domain is what proves the runtime behaviour; this is what
// stops a future edit from silently dropping the wrapper.
func TestSchemaFetchArraysSurviveASingleElement(t *testing.T) {
	s, err := ToolScript(ToolSchemaFetch)
	if err != nil {
		t.Fatalf("ToolScript: %v", err)
	}
	// Anchored on the call site, not on "<field> = @(...", because the six
	// fields are column-aligned with a variable run of spaces before "="; a
	// check keyed to the field name plus a single space would break on the
	// file's own formatting, not on a regression.
	for _, field := range []string{
		"auxiliaryClass", "systemAuxiliaryClass",
		"mayContain", "systemMayContain",
		"mustContain", "systemMustContain",
	} {
		callSite := "Convert-AdSchemaNames $_." + field + ")"
		wrapped := "= @(" + callSite
		if !strings.Contains(s, wrapped) {
			t.Errorf("the schema fetch script is missing %q; a single-element result would decode as a string, not an array", wrapped)
		}
		bare := "= (" + callSite
		if strings.Contains(s, bare) {
			t.Errorf("the schema fetch script has an unwrapped %q; a single-element result would decode as a string, not an array", bare)
		}
	}
}

// A tool shares the preamble and epilogue, which is what makes its credential
// handling, error shape and framing identical to every op's rather than merely
// similar.
func TestToolScriptSharesTheEnvelope(t *testing.T) {
	s, err := ToolScript(ToolSchemaFetch)
	if err != nil {
		t.Fatalf("ToolScript: %v", err)
	}
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"Import-Module ActiveDirectory -ErrorAction Stop",
		"ConvertTo-AdHashtable ($__adRaw | ConvertFrom-Json)",
		"$common['Credential']",
		"<<<TFAD:BEGIN>>>",
		"<<<TFAD:END>>>",
		"-Depth 6 -Compress",
		"(objectClass=attributeSchema)",
		"(objectClass=classSchema)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the schema fetch script is missing %q", want)
		}
	}
}

// TestCLMACLScriptsCompileAndCallHelpers pins the CLM ACL op variants added
// alongside the ConstrainedLanguage endpoint helpers: each op fragment must
// delegate to the matching helper function by name, and the fragment itself
// (not the shared preamble/epilogue, which legitimately use .NET) must stay
// inside what a ConstrainedLanguage caller is allowed to run.
func TestCLMACLScriptsCompileAndCallHelpers(t *testing.T) {
	cases := map[string]string{
		OpACLGrantCLM:  "Set-AdAce",
		OpACLReadCLM:   "Get-AdAce",
		OpACLRevokeCLM: "Remove-AdAce",
	}
	for op, fn := range cases {
		s, err := Script(op)
		if err != nil {
			t.Fatalf("Script(%q): %v", op, err)
		}
		if !strings.Contains(s, fn) {
			t.Errorf("%s must call %s", op, fn)
		}
		// Caller-scope CLM safety: the *fragment* must not construct .NET,
		// call methods on non-core types, or use any other construct a
		// ConstrainedLanguage caller cannot run -- static-type member access
		// ("::", covering "::new("), .GetType(), and .Clear() (e.g.
		// $Error.Clear()), alongside the original .NET-construction guards.
		// The preamble/epilogue legitimately use these; assert on the
		// fragment between them, never on the composed script as a whole.
		clmIllegal := []string{"::", "AddAccessRule(", ".GetType(", ".Clear("}
		frag := fragmentOnly(t, s)
		for _, forbidden := range clmIllegal {
			if strings.Contains(frag, forbidden) {
				t.Errorf("%s fragment contains CLM-illegal construct %q", op, forbidden)
			}
		}
	}
}

// fragmentOnly returns the op fragment with the shared preamble and epilogue
// stripped, so a CLM-safety assertion sees only the op's own text.
func fragmentOnly(t *testing.T, composed string) string {
	t.Helper()
	pre, err := files.ReadFile("preamble.ps1")
	if err != nil {
		t.Fatal(err)
	}
	epi, err := files.ReadFile("epilogue.ps1")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimPrefix(composed, string(pre))
	return strings.TrimSuffix(s, string(epi))
}

func TestScriptForRejectsUnknownDialect(t *testing.T) {
	if _, err := ScriptFor("nonsense", OpOURead); err == nil {
		t.Fatal("ScriptFor with an unknown dialect returned no error")
	}
}

func TestScriptForADWSMatchesScript(t *testing.T) {
	want, err := Script(OpOURead)
	if err != nil {
		t.Fatalf("Script: %v", err)
	}
	got, err := ScriptFor("adws", OpOURead)
	if err != nil {
		t.Fatalf("ScriptFor: %v", err)
	}
	if got != want {
		t.Fatal("ScriptFor(\"adws\", …) differs from Script(…)")
	}
}

// A fragment the dialect does not carry must be reported by name, so a
// half-finished dialect fails loudly on the missing op rather than silently
// running another dialect's script. Asserted on an op that exists in neither
// dialect, so this keeps testing the error path once coverage is complete.
func TestScriptForPSOpenADReportsMissingFragment(t *testing.T) {
	const missing = "no_such_op"
	_, err := ScriptFor("psopenad", missing)
	if err == nil {
		t.Fatal("expected an error for an op the dialect has no fragment for")
	}
	if !strings.Contains(err.Error(), "psopenad") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("error should name the dialect and the op, got: %v", err)
	}
}

// The psopenad dialect covers every op the adws dialect does.
func TestPSOpenADDialectCoverage(t *testing.T) {
	for _, op := range Ops() {
		if _, err := ScriptFor("psopenad", op); err != nil {
			t.Errorf("op %q: %v", op, err)
		}
	}
}

// A read of nTSecurityDescriptor that does not say WHICH parts of the
// descriptor it wants asks for all four, the SACL included. A caller without
// SeSecurityPrivilege is not refused that read -- Active Directory returns the
// attribute EMPTY, and PSOpenAD surfaces it as $null.
//
// That is why every read here must pass -SecurityMask, and why its absence is
// so dangerous: it does not fail on the developer's Domain Admin account, only
// on the least-privileged service account a real deployment uses. It then
// fails two ways at once -- Set-AdProtected calls .Insert() on the null DACL
// and throws InvokeMethodOnNull, while Convert-AdOU/Convert-AdUser quietly read
// every Deny ACE as absent, so `protected` and `canChangePassword` come back
// false no matter what the directory actually holds.
//
// Set-AdDacl already masks on the WRITE for a related reason (a descriptor
// carrying a SACL is refused with CONSTRAINT_ATT_TYPE). The read needs it too.
func TestPSOpenADReadsTheSecurityDescriptorWithAMask(t *testing.T) {
	pre, err := files.ReadFile("ops_psopenad/preamble.ps1")
	if err != nil {
		t.Fatalf("read psopenad preamble: %v", err)
	}
	for _, line := range strings.Split(string(pre), "\n") {
		if !strings.Contains(line, "Get-OpenADObject") {
			continue
		}
		if !strings.Contains(strings.ToLower(line), "ntsecuritydescriptor") {
			continue
		}
		if !strings.Contains(line, "-SecurityMask") {
			t.Errorf("Get-OpenADObject reads nTSecurityDescriptor without -SecurityMask:\n\t%s",
				strings.TrimSpace(line))
		}
	}
	// The property lists are handed to Get-OpenADObject by the op fragments, so
	// a mask on the call site is only half the story: a list naming the
	// descriptor commits every one of those call sites to masking.
	for _, decl := range []string{"$AD_PROPS_OU", "$AD_PROPS_USER"} {
		i := strings.Index(string(pre), decl)
		if i < 0 {
			t.Errorf("%s is gone; this guard no longer covers what it claims", decl)
		}
	}
}

// The op fragments are where those property lists are actually spent. Any
// fragment that asks for a descriptor must mask the request.
func TestPSOpenADFragmentsMaskTheirDescriptorReads(t *testing.T) {
	entries, err := files.ReadDir("ops_psopenad")
	if err != nil {
		t.Fatalf("read psopenad ops: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "preamble.ps1" || !strings.HasSuffix(e.Name(), ".ps1") {
			continue
		}
		b, err := files.ReadFile("ops_psopenad/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "Get-OpenADObject") && !strings.Contains(line, "Get-OpenADUser") {
				continue
			}
			l := strings.ToLower(line)
			asksForSD := strings.Contains(l, "ntsecuritydescriptor") ||
				strings.Contains(line, "$AD_PROPS_OU") || strings.Contains(line, "$AD_PROPS_USER")
			if asksForSD && !strings.Contains(line, "-SecurityMask") {
				t.Errorf("%s reads a security descriptor without -SecurityMask:\n\t%s",
					e.Name(), strings.TrimSpace(line))
			}
		}
	}
}

// PSOpenAD decodes AD's interval attributes - accountExpires, pwdLastSet - to
// DateTimeOffset, so the FILETIME sentinels do not survive as integers: 0
// arrives as 1601-01-01 and 0x7FFFFFFFFFFFFFFF as MaxValue. Comparing one to a
// number therefore silently never matches, which is how changePasswordAtLogon
// came to read back false for every user however the account was actually
// flagged.
//
// Both attributes must be read through a helper that knows the decoding.
func TestPSOpenADReadsIntervalAttributesThroughAHelper(t *testing.T) {
	pre, err := files.ReadFile("ops_psopenad/preamble.ps1")
	if err != nil {
		t.Fatalf("read psopenad preamble: %v", err)
	}
	helpers := map[string]string{
		"PwdLastSet":     "Test-AdMustChangePassword",
		"AccountExpires": "ConvertTo-AdIsoTime",
	}
	for _, line := range strings.Split(string(pre), "\n") {
		for attr, helper := range helpers {
			if !strings.Contains(line, "Get-AdPropValue") || !strings.Contains(line, "'"+attr+"'") {
				continue
			}
			if !strings.Contains(line, helper) {
				t.Errorf("%s is read without %s, so its FILETIME sentinel is compared "+
					"against a DateTimeOffset:\n\t%s", attr, helper, strings.TrimSpace(line))
			}
		}
	}
}

// The ActiveDirectory cmdlets supply conveniences that raw LDAP does not, and
// every psopenad bug found on the lab so far has been one of them going
// missing. Two are load-bearing enough to gate.
//
// New-ADComputer and New-ADServiceAccount append the trailing "$" that a
// computer-class sAMAccountName requires; New-OpenADObject writes exactly what
// it is given, and AD rejects the unsuffixed name with 0x523
// ERROR_INVALID_ACCOUNT_NAME. The Go side deliberately never suffixes it - see
// the comment on Computer.Update - so the fragment must.
func TestPSOpenADSuffixesComputerClassAccountNames(t *testing.T) {
	for _, name := range []string{"computer_create", "gmsa_create"} {
		b, err := files.ReadFile("ops_psopenad/" + name + ".ps1")
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		if !strings.Contains(src, "sAMAccountName") {
			t.Errorf("%s no longer writes sAMAccountName; this guard is stale", name)
			continue
		}
		if !strings.Contains(src, "ConvertTo-AdComputerSamAccountName") {
			t.Errorf("%s writes sAMAccountName without ConvertTo-AdComputerSamAccountName, "+
				"so an unsuffixed name reaches AD and is refused with 0x523", name)
		}
	}
}

// @($null) has length one, so `foreach ($x in @($maybeNull))` runs its body once
// with a null - the trap the preamble's ConvertTo-AdArray comment already
// warns about. group_members_read hit it on an EMPTY group and passed $null to
// Get-OpenADObject -Identity. The ADWS fragment iterates the bare property, so
// it runs zero times instead.
func TestPSOpenADDoesNotIterateAWrappedNullableProperty(t *testing.T) {
	b, err := files.ReadFile("ops_psopenad/group_members_read.ps1")
	if err != nil {
		t.Fatalf("read group_members_read: %v", err)
	}
	src := string(b)
	if strings.Contains(src, "@($g.Member)") {
		t.Error("group_members_read iterates @($g.Member), which on an EMPTY group is a " +
			"one-element array holding null, so Get-OpenADObject -Identity gets $null")
	}
	if !strings.Contains(src, "ConvertTo-AdArray") {
		t.Error("group_members_read no longer flattens the member set through " +
			"ConvertTo-AdArray, which is what drops the null an empty group produces")
	}
}

// msDS-ManagedPasswordInterval is the gMSA class's only systemMustContain
// attribute (confirmed against a live schema), so an LDAP add that omits it
// produces an incomplete object and AD refuses it with 0x207C
// OBJ_CLASS_VIOLATION. New-ADServiceAccount supplies the default; raw LDAP does
// not, so the fragment must write it unconditionally rather than only when the
// caller states it.
func TestPSOpenADAlwaysWritesTheGMSAPasswordInterval(t *testing.T) {
	b, err := files.ReadFile("ops_psopenad/gmsa_create.ps1")
	if err != nil {
		t.Fatalf("read gmsa_create: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "msDS-ManagedPasswordInterval") {
		t.Fatal("gmsa_create no longer writes msDS-ManagedPasswordInterval at all")
	}
	// The buggy form guarded the write behind the caller having stated it.
	if strings.Contains(src, "if ($c.ContainsKey('ManagedPasswordIntervalInDays')) {\n            $attrs['msDS-ManagedPasswordInterval']") {
		t.Error("gmsa_create writes msDS-ManagedPasswordInterval only when the caller states " +
			"it, so a gMSA created without one is refused with 0x207C OBJ_CLASS_VIOLATION")
	}
}

// PSOpenAD spells the SPN property differently per class: Get-OpenADComputer
// surfaces ServicePrincipalName, Get-OpenADServiceAccount surfaces
// ServicePrincipalNames. Convert-AdServiceAccount read the singular name, got
// null, and emitted an empty set - so a gMSA's SPNs never round-tripped, and
// Terraform failed the apply as an inconsistent result rather than reporting
// anything about SPNs.
func TestPSOpenADReadsSPNsUnderEitherSpelling(t *testing.T) {
	pre, err := files.ReadFile("ops_psopenad/preamble.ps1")
	if err != nil {
		t.Fatalf("read psopenad preamble: %v", err)
	}
	for _, line := range strings.Split(string(pre), "\n") {
		if !strings.Contains(line, "servicePrincipalNames") {
			continue // not an emitted SPN field
		}
		if !strings.Contains(line, "Get-AdSpnValue") {
			t.Errorf("an SPN field is read without Get-AdSpnValue, so it sees only one of the "+
				"two spellings PSOpenAD uses:\n\t%s", strings.TrimSpace(line))
		}
	}
}
