package adpwsh

import "time"

// OU is an organizational unit as this library reads it back.
type OU struct {
	GUID        string
	DN          string
	Name        string
	Container   string // derived from DN; never echoed by the script
	Description string
	Protected   bool
}

// Group is a security or distribution group.
type Group struct {
	GUID           string
	DN             string
	Name           string
	SamAccountName string
	Container      string
	Scope          GroupScope
	Category       GroupCategory
	Description    string
	ManagedBy      string
	SID            string
}

// Member is one entry read back from a group's membership.
type Member struct {
	GUID  string
	DN    string
	Class string // user, group, computer, foreignSecurityPrincipal, …
	SID   string
}

// User is a user account.
type User struct {
	GUID                  string
	DN                    string
	Name                  string
	SamAccountName        string
	UserPrincipalName     string
	DisplayName           string
	GivenName             string
	Surname               string
	Description           string
	Container             string
	Enabled               bool
	SID                   string
	ChangePasswordAtLogon bool
	CanChangePassword     bool
	PasswordExpires       bool
	AccountExpiration     *time.Time // nil means the account never expires
}

// GMSA is a group Managed Service Account as this library reads it back.
type GMSA struct {
	GUID                          string
	DN                            string
	Name                          string
	SamAccountName                string
	Container                     string
	SID                           string
	DNSHostName                   string
	Description                   string
	DisplayName                   string
	Enabled                       bool
	TrustedForDelegation          bool
	PrincipalsAllowed             []string // objectGUIDs, resolved from the DNs AD returns
	ServicePrincipalNames         []string
	KerberosEncryptionType        []string
	ManagedPasswordIntervalInDays int
	AccountExpiration             *time.Time // nil means never
}

// Computer is an Active Directory computer account (objectClass "computer").
// OperatingSystem* are read-only: the joined machine owns them.
type Computer struct {
	GUID                       string
	DN                         string
	Name                       string
	SamAccountName             string
	Container                  string
	SID                        string
	Enabled                    bool
	DNSHostName                string
	Description                string
	DisplayName                string
	Location                   string
	ManagedBy                  string // read back as a DN
	TrustedForDelegation       bool
	ServicePrincipalNames      []string
	AllowedToDelegateTo        []string // msDS-AllowedToDelegateTo (SPNs)
	PrincipalsAllowed          []string // RBCD principals, as objectGUIDs
	KerberosEncryptionType     []string
	AccountExpiration          *time.Time
	OperatingSystem            string
	OperatingSystemVersion     string
	OperatingSystemServicePack string
}

// GroupScope is the group's replication and membership scope.
type GroupScope string

const (
	GroupScopeGlobal      GroupScope = "global"
	GroupScopeDomainLocal GroupScope = "domainlocal"
	GroupScopeUniversal   GroupScope = "universal"
)

// GroupCategory distinguishes a security principal from a distribution list.
type GroupCategory string

const (
	GroupCategorySecurity     GroupCategory = "security"
	GroupCategoryDistribution GroupCategory = "distribution"
)

// cmdletValue maps a scope onto the -GroupScope parameter's accepted values.
func (s GroupScope) cmdletValue() (string, bool) {
	switch s {
	case GroupScopeGlobal:
		return "Global", true
	case GroupScopeDomainLocal:
		return "DomainLocal", true
	case GroupScopeUniversal:
		return "Universal", true
	default:
		return "", false
	}
}

func (c GroupCategory) cmdletValue() (string, bool) {
	switch c {
	case GroupCategorySecurity:
		return "Security", true
	case GroupCategoryDistribution:
		return "Distribution", true
	default:
		return "", false
	}
}

// OptTime is the three-state carrier a *time.Time cannot express: time.Time
// has no empty sentinel the way string does. The zero value leaves the
// attribute alone.
type OptTime struct {
	set   bool
	clear bool
	val   time.Time
}

// SetTime writes accountExpires.
func SetTime(t time.Time) OptTime { return OptTime{set: true, val: t} }

// ClearTime clears accountExpires, which in AD means "never expires".
func ClearTime() OptTime { return OptTime{clear: true} }

// IsSet reports whether a value should be written.
func (o OptTime) IsSet() bool { return o.set }

// IsClear reports whether the attribute should be cleared.
func (o OptTime) IsClear() bool { return o.clear }

// Value is meaningful only when IsSet reports true.
func (o OptTime) Value() time.Time { return o.val }

// String is the pointer helper for the tri-state spec fields. Named for how it
// reads at the call site: Description: adpwsh.String("x").
func String(s string) *string { return &s }

// Bool is the pointer helper for optional booleans.
func Bool(b bool) *bool { return &b }
