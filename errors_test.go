package adpwsh

import (
	"errors"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		code int
		want Kind
	}{
		// The code is authoritative where it is present.
		{"already exists by code", "Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException", 0x1392, KindAlreadyExists},
		{"no such object", "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException", 0x2030, KindNotFound},
		{"obj not found", "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException", 0x208D, KindNotFound},
		{"illegal modify", "Microsoft.ActiveDirectory.Management.ADIllegalModifyOperationException", 0x2077, KindConstraint},
		{"constraint violation", "Microsoft.ActiveDirectory.Management.ADInvalidOperationException", 0x202F, KindConstraint},
		{"unwilling to perform", "Microsoft.ActiveDirectory.Management.ADInvalidOperationException", 0x2035, KindConstraint},
		{"access denied", "Microsoft.ActiveDirectory.Management.ADException", 0x0005, KindDenied},
		{"insufficient rights", "Microsoft.ActiveDirectory.Management.ADException", 0x2098, KindDenied},
		{"password restriction", "Microsoft.ActiveDirectory.Management.ADPasswordException", 0x052D, KindPassword},
		{"rpc unavailable", "Microsoft.ActiveDirectory.Management.ADServerDownException", 0x06BA, KindTransient},
		{"ds busy", "Microsoft.ActiveDirectory.Management.ADException", 0x200E, KindTransient},
		// The code overrides the type: an ADException carrying the
		// already-exists code is an already-exists, not an unknown.
		{"code beats type", "Microsoft.ActiveDirectory.Management.ADException", 0x1392, KindAlreadyExists},
		// With no code, the type is the only signal.
		{"type only, not found", "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException", 0, KindNotFound},
		{"type only, resolution", "Microsoft.ActiveDirectory.Management.ADIdentityResolutionException", 0, KindNotFound},
		{"type only, multiple matches", "Microsoft.ActiveDirectory.Management.ADMultipleMatchingIdentitiesException", 0, KindConstraint},
		{"type only, complexity", "Microsoft.ActiveDirectory.Management.ADPasswordComplexityException", 0, KindPassword},
		{"type only, referral", "Microsoft.ActiveDirectory.Management.ADReferralException", 0, KindReferral},
		{"type only, filter parsing", "Microsoft.ActiveDirectory.Management.ADFilterParsingException", 0, KindConstraint},
		{"type only, server down", "Microsoft.ActiveDirectory.Management.ADServerDownException", 0, KindTransient},
		{"unauthorized access", "System.UnauthorizedAccessException", 0, KindDenied},
		// Fail closed: the base types and the four the assembly names but no
		// documentation describes are named branches, never guesses.
		{"base ADException", "Microsoft.ActiveDirectory.Management.ADException", 0, KindUnknown},
		{"ADCustomException", "Microsoft.ActiveDirectory.Management.ADCustomException", 0, KindUnknown},
		{"ADPipelineException", "Microsoft.ActiveDirectory.Management.ADPipelineException", 0, KindUnknown},
		{"ADRecordException", "Microsoft.ActiveDirectory.Management.ADRecordException", 0, KindUnknown},
		{"ADSystemException", "Microsoft.ActiveDirectory.Management.ADSystemException", 0, KindUnknown},
		{"never seen before", "Some.Other.Exception", 0, KindUnknown},
		{"unknown code, unknown type", "Some.Other.Exception", 0x9999, KindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.typ, tt.code); got != tt.want {
				t.Errorf("Classify(%q, %#x) = %v, want %v", tt.typ, tt.code, got, tt.want)
			}
		})
	}
}

// Guessing that an unrecognised error is transient turns a permission problem
// into a hang, so only KindTransient is ever retried.
func TestOnlyTransientRetries(t *testing.T) {
	for k := KindUnknown; k <= KindTooManyResults; k++ {
		if got := k.retryable(); got != (k == KindTransient) {
			t.Errorf("Kind(%v).retryable() = %v", k, got)
		}
	}
}

func TestErrorIsAndAs(t *testing.T) {
	err := error(&Error{
		Kind:          KindNotFound,
		Op:            "User.Get",
		Identity:      "guid:9f2c",
		ExceptionType: "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException",
		Code:          0x2030,
		ServerMessage: "The directory service cannot find the object",
	})

	if !errors.Is(err, ErrNotFound) {
		t.Error("errors.Is(err, ErrNotFound) must match on Kind")
	}
	if errors.Is(err, ErrAlreadyExists) {
		t.Error("errors.Is must not match a different Kind")
	}
	var target *Error
	if !errors.As(err, &target) {
		t.Fatal("errors.As must recover the full detail")
	}
	if target.Code != 0x2030 || target.ServerMessage == "" {
		t.Errorf("recovered error lost detail: %+v", target)
	}
	msg := err.Error()
	for _, want := range []string{"User.Get", "not found", "ADIdentityNotFoundException"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, missing %q", msg, want)
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	inner := errors.New("dial tcp: connection refused")
	err := &Error{Kind: KindTransport, Op: "ssh.Run", Err: inner}
	if !errors.Is(err, inner) {
		t.Error("Unwrap must expose the wrapped cause")
	}
	if !errors.Is(err, ErrTransport) {
		t.Error("Kind sentinel must still match through Unwrap")
	}
}
