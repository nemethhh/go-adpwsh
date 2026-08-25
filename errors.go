package adpwsh

import (
	"fmt"
	"strings"
)

// Kind is the normalized condition a caller switches on. Adding a condition
// later adds a Kind, not a type: the public surface does not track Microsoft's
// exception list.
type Kind int

const (
	KindUnknown Kind = iota
	KindNotFound
	KindAlreadyExists
	KindDenied
	KindConstraint
	KindPassword
	KindReferral
	// KindTransient means the operation provably did not execute: the
	// failure occurred before the script (or, for a transport, the request
	// carrying it) was ever sent, so re-issuing the identical script and
	// payload cannot duplicate a side effect. This is the bar a producer of
	// KindTransient must clear — not "this looks like it might be worth
	// retrying," but "nothing happened, by construction, every time." An AD
	// result code that comes back through the envelope (RPC_S_SERVER_BUSY
	// and friends in classByCode) clears it: the script ran, the cmdlet was
	// attempted, and AD refused it before doing anything. A transport-level
	// failure clears it only when it is raised by a pre-send check (a
	// semaphore, a circuit breaker, a not-yet-connected guard) that runs
	// before any bytes carrying the script leave the process.
	//
	// Anything that merely *might* not have executed is not transient, and
	// must map to KindTransport (or another non-retryable Kind) instead. In
	// particular, a context cancellation or deadline observed while awaiting
	// a response is not transient: depending on the transport, the script
	// may already have reached the server before the deadline fired, so the
	// failure and a completed execution are indistinguishable from here.
	// This is the exact bug that once made transport/psrp/wrap.go's
	// mapExecuteError treat context.Canceled/context.DeadlineExceeded as
	// KindTransient — up to Retry.MaxAttempts re-issues of an operation that
	// may have already run. See mapExecuteError's doc for the WSMan-specific
	// mechanics and why a caller-side cancellation loses nothing by staying
	// non-retryable (core.backoff already aborts on the caller's own
	// ctx.Done()).
	KindTransient
	KindTransport
	KindInvalidAttribute
	KindSchema
	// KindReplication means the write succeeded and the replication wait did
	// not complete. It is never retried, and the caller must persist the model
	// it was returned alongside.
	KindReplication
	// KindTooManyResults means a search matched more than its size limit. It is
	// never retried; the caller narrows the filter or raises the limit.
	KindTooManyResults
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not found"
	case KindAlreadyExists:
		return "already exists"
	case KindDenied:
		return "access denied"
	case KindConstraint:
		return "constraint violation"
	case KindPassword:
		return "password rejected"
	case KindReferral:
		return "referral"
	case KindTransient:
		return "transient"
	case KindTransport:
		return "transport failure"
	case KindInvalidAttribute:
		return "invalid attribute"
	case KindSchema:
		return "schema error"
	case KindReplication:
		return "replication wait timed out"
	case KindTooManyResults:
		return "too many results"
	default:
		return "unknown"
	}
}

// retryable is deliberately narrow, and narrow for two different reasons.
// Retrying an access-denied or a duplicate-object error only delays a clear
// message — that failure is final, retrying wastes time. Retrying anything
// that is not KindTransient risks something worse than wasted time: KindTransient
// is the only Kind whose contract guarantees the operation provably did not
// execute (see its doc), so it is the only Kind core.exec may safely
// re-issue the identical script and payload against. A Kind added later must
// not be folded into this check unless it can make that same guarantee.
func (k Kind) retryable() bool { return k == KindTransient }

// Error is the single error type this library returns. AD's raw detail is
// carried alongside the normalized Kind so a caller can render an exact
// message without switching on Microsoft's type names.
type Error struct {
	Kind          Kind   // the only thing callers switch on
	Op            string // "User.Create"
	Identity      string // the identity acted on, in form:value notation
	ExceptionType string // verbatim, e.g. …ADIdentityNotFoundException
	Code          int    // Win32 code; decode via MS-ERREF
	ServerMessage string // the DC's own words, via IHasServerErrorMessage
	FQID          string // cmdlet-specific; diagnostics only
	Target        string
	Tombstoned    bool // set when an already-exists was traced to a deleted object
	Err           error
}

func (e *Error) Error() string {
	var sb strings.Builder
	if e.Op != "" {
		sb.WriteString(e.Op)
		sb.WriteString(": ")
	}
	sb.WriteString(e.Kind.String())
	if e.Identity != "" {
		fmt.Fprintf(&sb, " (%s)", e.Identity)
	}
	if e.ServerMessage != "" {
		sb.WriteString(": ")
		sb.WriteString(e.ServerMessage)
	} else if e.Err != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Err.Error())
	}
	if e.ExceptionType != "" {
		fmt.Fprintf(&sb, " [%s", shortTypeName(e.ExceptionType))
		if e.Code != 0 {
			fmt.Fprintf(&sb, " %#x", e.Code)
		}
		sb.WriteString("]")
	}
	return sb.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches the Kind sentinels, so errors.Is(err, ErrNotFound) works without
// exposing the sentinel's concrete type.
func (e *Error) Is(target error) bool {
	s, ok := target.(kindSentinel)
	return ok && s.kind == e.Kind
}

type kindSentinel struct{ kind Kind }

func (s kindSentinel) Error() string { return s.kind.String() }

// Kind sentinels for errors.Is.
var (
	ErrNotFound         error = kindSentinel{KindNotFound}
	ErrAlreadyExists    error = kindSentinel{KindAlreadyExists}
	ErrDenied           error = kindSentinel{KindDenied}
	ErrConstraint       error = kindSentinel{KindConstraint}
	ErrPassword         error = kindSentinel{KindPassword}
	ErrReferral         error = kindSentinel{KindReferral}
	ErrTransient        error = kindSentinel{KindTransient}
	ErrTransport        error = kindSentinel{KindTransport}
	ErrInvalidAttribute error = kindSentinel{KindInvalidAttribute}
	ErrSchema           error = kindSentinel{KindSchema}
	ErrReplication      error = kindSentinel{KindReplication}
	ErrTooManyResults   error = kindSentinel{KindTooManyResults}
)

func shortTypeName(full string) string {
	if i := strings.LastIndexByte(full, '.'); i >= 0 {
		return full[i+1:]
	}
	return full
}

// classByCode maps Win32 error codes (MS-ERREF) to a Kind. The module builds
// the exception from the code, so the code is the more precise of the two and
// wins wherever it is present.
var classByCode = map[int]Kind{
	0x0005: KindDenied,        // ERROR_ACCESS_DENIED
	0x052D: KindPassword,      // ERROR_PASSWORD_RESTRICTION
	0x06BA: KindTransient,     // RPC_S_SERVER_UNAVAILABLE
	0x06BB: KindTransient,     // RPC_S_SERVER_TOO_BUSY
	0x1392: KindAlreadyExists, // ERROR_OBJECT_ALREADY_EXISTS
	0x200E: KindTransient,     // ERROR_DS_BUSY
	0x2014: KindConstraint,    // ERROR_DS_OBJ_CLASS_VIOLATION
	0x2015: KindConstraint,    // ERROR_DS_CANT_ON_NON_LEAF
	0x202B: KindReferral,      // ERROR_DS_REFERRAL
	0x202F: KindConstraint,    // ERROR_DS_CONSTRAINT_VIOLATION
	0x2030: KindNotFound,      // ERROR_DS_NO_SUCH_OBJECT
	0x2035: KindConstraint,    // ERROR_DS_UNWILLING_TO_PERFORM
	0x2037: KindConstraint,    // ERROR_DS_NAMING_VIOLATION
	0x2071: KindAlreadyExists, // ERROR_DS_OBJ_STRING_NAME_EXISTS: a name already in use. New-ADOrganizationalUnit on a duplicate raises ADException carrying this code, not the 0x1392 identity form users/groups raise.
	0x2076: KindConstraint,    // ERROR_DS_ATT_IS_NOT_ON_OBJ
	0x2077: KindConstraint,    // ERROR_DS_ILLEGAL_MOD_OPERATION
	0x207E: KindConstraint,    // ERROR_DS_ATT_ALREADY_EXISTS
	0x2098: KindDenied,        // ERROR_DS_INSUFF_ACCESS_RIGHTS
	0x208D: KindNotFound,      // ERROR_DS_OBJ_NOT_FOUND
	0x20F6: KindTransient,     // ERROR_DS_DRA_BUSY
	0x2118: KindConstraint,    // ERROR_DS_NAME_ERROR_NO_MAPPING
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
}

// Classify normalizes an AD exception into a Kind. It fails closed: an
// unrecognized (type, code) pair is KindUnknown and is never retried.
func Classify(exceptionType string, code int) Kind {
	if k, ok := classByCode[code]; ok {
		return k
	}
	if k, ok := classByType[shortTypeName(exceptionType)]; ok {
		return k
	}
	return KindUnknown
}
