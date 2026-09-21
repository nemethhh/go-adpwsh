package adpwsh

import (
	"time"

	"github.com/nemethhh/go-adcore"
)

// The directory vocabulary now lives in go-adcore, which the native-LDAP
// backend shares. These aliases keep this module's public API byte-identical:
// adpwsh.OU and adcore.OU are the same type, not two convertible ones, so a
// consumer passing either to either module compiles unchanged.

type (
	OU            = adcore.OU
	Group         = adcore.Group
	User          = adcore.User
	GMSA          = adcore.GMSA
	Computer      = adcore.Computer
	Member        = adcore.Member
	GroupScope    = adcore.GroupScope
	GroupCategory = adcore.GroupCategory
	OptTime       = adcore.OptTime

	OUSpec        = adcore.OUSpec
	GroupSpec     = adcore.GroupSpec
	UserSpec      = adcore.UserSpec
	GMSASpec      = adcore.GMSASpec
	ComputerSpec  = adcore.ComputerSpec
	DeleteOptions = adcore.DeleteOptions

	Identity    = adcore.Identity
	Secret      = adcore.Secret
	Query       = adcore.Query
	SearchScope = adcore.SearchScope
	Kind        = adcore.Kind
	RetryConfig = adcore.RetryConfig
	Error       = adcore.Error

	ACEType        = adcore.ACEType
	Right          = adcore.Right
	Inheritance    = adcore.Inheritance
	ACE            = adcore.ACE
	ACESpec        = adcore.ACESpec
	SchemaRef      = adcore.SchemaRef
	SchemaRefKind  = adcore.SchemaRefKind
	DelegationTask = adcore.DelegationTask

	// DelegationClient keeps its name here although the type is called
	// Delegation in adcore: it is reached as Client.Delegation, and the
	// provider names the type directly.
	DelegationClient = adcore.Delegation
)

const (
	KindUnknown          = adcore.KindUnknown
	KindNotFound         = adcore.KindNotFound
	KindAlreadyExists    = adcore.KindAlreadyExists
	KindDenied           = adcore.KindDenied
	KindConstraint       = adcore.KindConstraint
	KindPassword         = adcore.KindPassword
	KindReferral         = adcore.KindReferral
	KindTransient        = adcore.KindTransient
	KindTransport        = adcore.KindTransport
	KindInvalidAttribute = adcore.KindInvalidAttribute
	KindSchema           = adcore.KindSchema
	KindReplication      = adcore.KindReplication
	KindTooManyResults   = adcore.KindTooManyResults
	KindUnsupported      = adcore.KindUnsupported

	SearchScopeBase     = adcore.SearchScopeBase
	SearchScopeOneLevel = adcore.SearchScopeOneLevel
	SearchScopeSubtree  = adcore.SearchScopeSubtree

	GroupScopeGlobal      = adcore.GroupScopeGlobal
	GroupScopeDomainLocal = adcore.GroupScopeDomainLocal
	GroupScopeUniversal   = adcore.GroupScopeUniversal

	GroupCategorySecurity     = adcore.GroupCategorySecurity
	GroupCategoryDistribution = adcore.GroupCategoryDistribution

	InheritanceThis        = adcore.InheritanceThis
	InheritanceDescendants = adcore.InheritanceDescendants
	InheritanceChildren    = adcore.InheritanceChildren

	ACEAllow = adcore.ACEAllow
	ACEDeny  = adcore.ACEDeny

	RefAttribute     = adcore.RefAttribute
	RefClass         = adcore.RefClass
	RefExtendedRight = adcore.RefExtendedRight

	TaskResetUserPasswords    = adcore.TaskResetUserPasswords
	TaskManageUsers           = adcore.TaskManageUsers
	TaskModifyGroupMembership = adcore.TaskModifyGroupMembership
	TaskManageGroups          = adcore.TaskManageGroups
)

var (
	ErrNotFound         = adcore.ErrNotFound
	ErrAlreadyExists    = adcore.ErrAlreadyExists
	ErrDenied           = adcore.ErrDenied
	ErrConstraint       = adcore.ErrConstraint
	ErrPassword         = adcore.ErrPassword
	ErrReferral         = adcore.ErrReferral
	ErrTransient        = adcore.ErrTransient
	ErrTransport        = adcore.ErrTransport
	ErrInvalidAttribute = adcore.ErrInvalidAttribute
	ErrSchema           = adcore.ErrSchema
	ErrReplication      = adcore.ErrReplication
	ErrTooManyResults   = adcore.ErrTooManyResults
	ErrUnsupported      = adcore.ErrUnsupported
)

// Constructors forward rather than alias, so their documentation stays with
// this module's API surface.

// ByGUID identifies an object by objectGUID. This is the canonical form: it
// survives rename and move, which DN and sAMAccountName do not.
func ByGUID(guid string) Identity { return adcore.ByGUID(guid) }

// ByDN identifies an object by distinguished name.
func ByDN(dn string) Identity { return adcore.ByDN(dn) }

// BySID identifies a security principal by SID.
func BySID(sid string) Identity { return adcore.BySID(sid) }

// BySAM identifies a security principal by sAMAccountName.
func BySAM(sam string) Identity { return adcore.BySAM(sam) }

// NewSecret wraps a plaintext password.
func NewSecret(s string) Secret { return adcore.NewSecret(s) }

// String is the pointer helper for the tri-state spec fields.
func String(s string) *string { return adcore.String(s) }

// Bool is the pointer helper for optional booleans.
func Bool(b bool) *bool { return adcore.Bool(b) }

// Int is the pointer helper for optional integers.
func Int(i int) *int { return adcore.Int(i) }

// SetTime writes accountExpires.
func SetTime(t time.Time) OptTime { return adcore.SetTime(t) }

// ClearTime clears accountExpires, which in AD means "never expires".
func ClearTime() OptTime { return adcore.ClearTime() }

// EscapeFilter escapes one LDAP assertion value per RFC 4515.
func EscapeFilter(value string) string { return adcore.EscapeFilter(value) }

// Equal builds an equality assertion "(attr=<escaped value>)".
func Equal(attr, value string) string { return adcore.Equal(attr, value) }

// And composes a conjunction.
func And(terms ...string) string { return adcore.And(terms...) }

// Tasks returns every delegation task name, in a stable order.
func Tasks() []DelegationTask { return adcore.Tasks() }
