package adpwsh

import (
	"strings"

	"github.com/nemethhh/go-adcore"
)

// The Kind vocabulary, the Error type, the sentinels and the MS-ERREF code
// table all live in go-adcore now, re-exported from alias.go. What stays here
// is what keys on PowerShell: the exception type names the ActiveDirectory
// module raises.

func shortTypeName(full string) string {
	if i := strings.LastIndexByte(full, '.'); i >= 0 {
		return full[i+1:]
	}
	return full
}

// classByType maps the short exception type name to a Kind, used when the
// exception carried no ErrorCode. The 13 AD types are the ones the shipping
// Microsoft.ActiveDirectory.Management assembly names; the four below them are
// named by the assembly with no documentation anywhere, so they enter as
// fail-closed entries — a first encounter is a named branch, not an unknown.
var classByType = map[string]Kind{
	"ADIdentityNotFoundException":           KindNotFound,
	"ADIdentityResolutionException":         KindNotFound,
	"ADIdentityAlreadyExistsException":      KindAlreadyExists,
	"ADMultipleMatchingIdentitiesException": KindConstraint,
	"ADIllegalModifyOperationException":     KindConstraint,
	"ADInvalidOperationException":           KindConstraint,
	"ADFilterParsingException":              KindConstraint,
	"ADPasswordException":                   KindPassword,
	"ADInvalidPasswordException":            KindPassword,
	"ADPasswordComplexityException":         KindPassword,
	"ADServerDownException":                 KindTransient,
	"ADReferralException":                   KindReferral,
	"ADException":                           KindUnknown,
	"ADCustomException":                     KindUnknown,
	"ADPipelineException":                   KindUnknown,
	"ADRecordException":                     KindUnknown,
	"ADSystemException":                     KindUnknown,
	"UnauthorizedAccessException":           KindDenied,

	// PSOpenAD dialect. Cmdlet-level failures carry no Win32 code, so they are
	// classified on the type name alone. shortTypeName strips the namespace, so
	// these are keyed on the short name exactly as the AD types above are.
	//
	// LDAPException maps to KindUnknown deliberately: it is a carrier type whose
	// meaning lives in the Win32 code, and Classify consults classByCode first.
	// Mapping it to anything else would mask a code the table does not yet know,
	// and KindUnknown is never retried.
	"ItemNotFoundException": KindNotFound,
	"LDAPException":         KindUnknown,
}

// Classify normalizes an AD exception into a Kind. It fails closed: an
// unrecognized (type, code) pair is KindUnknown and is never retried.
//
// The Win32 code table is shared with the LDAP backend and lives in adcore;
// only the exception-name table below is PowerShell's, so only it stayed here.
// The code still wins wherever it is present, because the ActiveDirectory
// module builds the exception from it.
func Classify(exceptionType string, code int) Kind {
	if k, ok := adcore.ClassifyCode(code); ok {
		return k
	}
	if k, ok := classByType[shortTypeName(exceptionType)]; ok {
		return k
	}
	return KindUnknown
}

// classify fills in the Kind adcore.PresenceCheck cannot derive for itself.
// The probe hands back a .NET exception type name and a Win32 code, and only
// this module knows how to read the first — which is the whole reason
// ConfirmAbsent takes the classification as a field rather than making it.
func classify(p adcore.PresenceCheck) adcore.PresenceCheck {
	p.Kind = Classify(p.ExceptionType, p.ErrorCode)
	return p
}
