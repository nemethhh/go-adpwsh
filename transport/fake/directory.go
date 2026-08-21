package fake

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nemethhh/go-adpwsh/internal/addn"
)

// DirectoryObject is one object in the fake directory.
type DirectoryObject struct {
	GUID    string
	Class   string // organizationalUnit, group or user
	DN      string
	Data    map[string]any
	Deleted bool
}

// Directory is a small in-memory Active Directory: enough to answer the
// operations go-adpwsh issues, enforce uniqueness and not-found, count an OU's
// children, and keep a tombstone after a delete. It exists so a consumer can
// drive a full resource lifecycle with no Windows VM.
//
// It is not a simulator. Anything the library does not ask for is not here.
type Directory struct {
	mu      sync.Mutex
	server  string
	dnc     string
	objects map[string]*DirectoryObject // by GUID
	seq     int

	// Passwords records every password ever set, so a test can assert that a
	// rotation actually happened.
	Passwords map[string][]string
}

// NewDirectory returns a directory rooted at DC=corp,DC=local, served by
// dc01.corp.local.
func NewDirectory() *Directory {
	return &Directory{
		server:    "dc01.corp.local",
		dnc:       "DC=corp,DC=local",
		objects:   map[string]*DirectoryObject{},
		Passwords: map[string][]string{},
	}
}

// Transport returns a Transport wired to this directory.
func (d *Directory) Transport() *Transport { return New(d.Handle) }

// Objects returns a snapshot, GUID-ordered, including tombstones.
func (d *Directory) Objects() []DirectoryObject {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DirectoryObject, 0, len(d.objects))
	for _, o := range d.objects {
		copyData := make(map[string]any, len(o.Data))
		for k, v := range o.Data {
			copyData[k] = v
		}
		out = append(out, DirectoryObject{GUID: o.GUID, Class: o.Class, DN: o.DN, Data: copyData, Deleted: o.Deleted})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GUID < out[j].GUID })
	return out
}

func notFound(id string) Response {
	return Fail("Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException",
		fmt.Sprintf("Cannot find an object with identity: '%s'", id), 0x208D)
}

func alreadyExists(dn string) Response {
	return Fail("Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException",
		fmt.Sprintf("The object %s already exists", dn), 0x1392)
}

func (d *Directory) nextGUID() string {
	d.seq++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", d.seq)
}

// find resolves any of the identity forms the cmdlets accept.
func (d *Directory) find(identity string) *DirectoryObject {
	for _, o := range d.objects {
		if o.Deleted {
			continue
		}
		if o.GUID == identity ||
			strings.EqualFold(o.DN, identity) ||
			asString(o.Data["samAccountName"]) == identity ||
			asString(o.Data["sid"]) == identity {
			return o
		}
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func splat(payload map[string]any, key string) map[string]any {
	m, _ := payload[key].(map[string]any)
	return m
}

// Handle answers one call. It is the fake's whole dispatch table.
func (d *Directory) Handle(c Call) Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch c.Op {
	case "rootdse":
		return OK(map[string]any{
			"dnsHostName":          d.server,
			"defaultNamingContext": d.dnc,
			"schemaNamingContext":  "CN=Schema,CN=Configuration," + d.dnc,
		})
	case "dclist":
		return OK(map[string]any{"hostNames": []any{d.server}})
	case "replicate":
		return OK(map[string]any{"synced": true})
	case "replicate_verify":
		targets, _ := c.Payload["targets"].([]any)
		results := make([]any, 0, len(targets))
		for _, t := range targets {
			results = append(results, map[string]any{"target": t, "present": true})
		}
		return OK(map[string]any{"results": results})
	case "deleted_probe":
		return d.handleDeletedProbe(c)
	case "ou_create":
		return d.handleCreate(c, "organizationalUnit")
	case "group_create":
		return d.handleCreate(c, "group")
	case "user_create":
		return d.handleCreate(c, "user")
	case "ou_read", "group_read", "user_read":
		o := d.find(asString(c.Payload["identity"]))
		if o == nil {
			return notFound(asString(c.Payload["identity"]))
		}
		return OK(d.project(o))
	case "ou_search":
		return d.handleSearch(c, "organizationalUnit")
	case "group_search":
		return d.handleSearch(c, "group")
	case "user_search":
		return d.handleSearch(c, "user")
	case "ou_update", "group_update", "user_update":
		return d.handleUpdate(c)
	case "ou_delete":
		return d.handleOUDelete(c)
	case "group_delete", "user_delete":
		return d.handleDelete(c)
	case "user_setpassword":
		o := d.find(asString(c.Payload["identity"]))
		if o == nil {
			return notFound(asString(c.Payload["identity"]))
		}
		d.Passwords[o.GUID] = append(d.Passwords[o.GUID], asString(c.Payload["password"]))
		return OK(map[string]any{"reset": true})
	case "group_members_read":
		return d.handleMembersRead(c)
	case "group_members_add":
		return d.handleMembersAdd(c)
	case "group_members_remove":
		return d.handleMembersRemove(c)
	case "group_member_check":
		return d.handleMemberCheck(c)
	case "schema_resolve":
		return d.handleSchemaResolve(c)
	default:
		return Fail("Microsoft.ActiveDirectory.Management.ADException",
			fmt.Sprintf("fake.Directory does not implement op %q", c.Op), 0)
	}
}

// rdnPrefix is the attribute an object of this class is named by (rdnAttId).
func rdnPrefix(class string) string {
	if class == "organizationalUnit" {
		return "OU="
	}
	return "CN="
}

// buildDN names an object the way a directory does: the RDN value is escaped
// per RFC 4514, so a name containing a comma stays one component. Real AD
// never returns "OU=Sales, EMEA,DC=corp,DC=local" — it returns
// "OU=Sales\, EMEA,DC=corp,DC=local" — and a fake that concatenates instead
// hands its consumer a DN whose parent parses as "EMEA,DC=corp,DC=local".
func buildDN(class, name, container string) string {
	return rdnPrefix(class) + addn.EscapeValue(name) + "," + container
}

func (d *Directory) handleCreate(c Call, class string) Response {
	create := splat(c.Payload, "create")
	name := asString(create["Name"])
	container := asString(create["Path"])
	dn := buildDN(class, name, container)

	for _, o := range d.objects {
		if strings.EqualFold(o.DN, dn) && !o.Deleted {
			return alreadyExists(dn)
		}
		if !o.Deleted && class != "organizationalUnit" &&
			asString(o.Data["samAccountName"]) != "" &&
			asString(o.Data["samAccountName"]) == asString(create["SamAccountName"]) {
			return alreadyExists(o.DN)
		}
		// A tombstone still holds the name, which is the condition rule 8
		// exists to name.
		if o.Deleted && (strings.EqualFold(o.DN, dn) ||
			(asString(o.Data["samAccountName"]) != "" &&
				asString(o.Data["samAccountName"]) == asString(create["SamAccountName"]))) {
			return alreadyExists(dn)
		}
	}

	guid := d.nextGUID()
	obj := &DirectoryObject{GUID: guid, Class: class, DN: dn, Data: map[string]any{
		"objectGUID":        guid,
		"distinguishedName": dn,
		"name":              name,
	}}
	switch class {
	case "organizationalUnit":
		obj.Data["description"] = ""
		obj.Data["protected"] = true
	case "group":
		obj.Data["samAccountName"] = ""
		obj.Data["scope"] = "global"
		obj.Data["category"] = "security"
		obj.Data["description"] = ""
		obj.Data["managedBy"] = ""
		obj.Data["sid"] = "S-1-5-21-1-2-3-" + fmt.Sprint(1000+d.seq)
	case "user":
		for _, k := range []string{"samAccountName", "userPrincipalName", "displayName", "givenName", "surname", "description"} {
			obj.Data[k] = ""
		}
		obj.Data["enabled"] = false
		obj.Data["sid"] = "S-1-5-21-1-2-3-" + fmt.Sprint(1000+d.seq)
		obj.Data["changePasswordAtLogon"] = false
		obj.Data["canChangePassword"] = true
		obj.Data["passwordExpires"] = true
		obj.Data["accountExpirationDate"] = nil
	}
	d.applySplat(obj, create)
	if pw := asString(c.Payload["password"]); pw != "" {
		d.Passwords[guid] = append(d.Passwords[guid], pw)
	}
	d.objects[guid] = obj
	return OK(d.project(obj))
}

// paramToField maps a cmdlet parameter to the model field it writes. The two
// inverted rows are why the mapping is a table rather than a name match.
var paramToField = map[string]string{
	"Description":                     "description",
	"DisplayName":                     "displayName",
	"GivenName":                       "givenName",
	"Surname":                         "surname",
	"UserPrincipalName":               "userPrincipalName",
	"SamAccountName":                  "samAccountName",
	"ManagedBy":                       "managedBy",
	"Enabled":                         "enabled",
	"ChangePasswordAtLogon":           "changePasswordAtLogon",
	"AccountExpirationDate":           "accountExpirationDate",
	"ProtectedFromAccidentalDeletion": "protected",
}

// clearToField maps an LDAP name in -Clear to the model field it empties.
var clearToField = map[string]string{
	"description":       "description",
	"displayName":       "displayName",
	"givenName":         "givenName",
	"sn":                "surname",
	"userPrincipalName": "userPrincipalName",
	"managedBy":         "managedBy",
	"accountExpires":    "accountExpirationDate",
}

func (d *Directory) applySplat(o *DirectoryObject, s map[string]any) {
	for param, v := range s {
		switch param {
		case "Name", "Path", "Identity", "Add", "Remove", "Replace", "Clear":
			continue
		case "CannotChangePassword":
			o.Data["canChangePassword"] = v != true
		case "PasswordNeverExpires":
			o.Data["passwordExpires"] = v != true
		case "GroupScope":
			o.Data["scope"] = strings.ToLower(asString(v))
		case "GroupCategory":
			o.Data["category"] = strings.ToLower(asString(v))
		default:
			if field, ok := paramToField[param]; ok {
				o.Data[field] = v
			}
		}
	}
	if clear, ok := s["Clear"].([]any); ok {
		for _, name := range clear {
			field, ok := clearToField[asString(name)]
			if !ok {
				continue
			}
			if field == "accountExpirationDate" {
				o.Data[field] = nil
				continue
			}
			o.Data[field] = ""
		}
	}
}

func (d *Directory) handleUpdate(c Call) Response {
	o := d.find(asString(c.Payload["identity"]))
	if o == nil {
		return notFound(asString(c.Payload["identity"]))
	}
	if set := splat(c.Payload, "set"); set != nil {
		d.applySplat(o, set)
	}
	if rename := splat(c.Payload, "rename"); rename != nil {
		o.Data["name"] = asString(rename["NewName"])
		o.DN = buildDN(o.Class, asString(rename["NewName"]), parentOf(o.DN))
		o.Data["distinguishedName"] = o.DN
	}
	if move := splat(c.Payload, "move"); move != nil {
		// Real AD refuses to move a protected object: the flag denies Delete on
		// it, which is the right a move is authorised through. Modelling that
		// here is the point of the fake — without it the provider passed every
		// fake-backed test and still could not move an OU carrying AD's own
		// default.
		if c.Payload["unprotectBeforeMove"] == true {
			o.Data["protected"] = false
		}
		if o.Data["protected"] == true {
			return Fail("System.UnauthorizedAccessException", "Access is denied", 0x5)
		}
		o.DN = buildDN(o.Class, asString(o.Data["name"]), asString(move["TargetPath"]))
		o.Data["distinguishedName"] = o.DN
	}
	// Applied last, mirroring the script: protection restored once the object
	// is where it belongs.
	if p, ok := c.Payload["protect"]; ok {
		o.Data["protected"] = p == true
	}
	return OK(d.project(o))
}

func (d *Directory) handleOUDelete(c Call) Response {
	id := asString(c.Payload["identity"])
	o := d.find(id)
	if o == nil {
		return notFound(id)
	}
	children := 0
	for _, other := range d.objects {
		if other.Deleted || other.GUID == o.GUID {
			continue
		}
		if strings.EqualFold(parentOf(other.DN), o.DN) {
			children++
		}
	}
	if children > 0 {
		return OK(map[string]any{"deleted": false, "childCount": children})
	}
	if c.Payload["unprotect"] == true {
		o.Data["protected"] = false
	}
	if o.Data["protected"] == true {
		return Fail("Microsoft.ActiveDirectory.Management.ADIllegalModifyOperationException",
			"Access is denied: the object is protected from accidental deletion", 0x2077)
	}
	o.Deleted = true
	return OK(map[string]any{"deleted": true, "childCount": 0, "verify": absentVerdict()})
}

func (d *Directory) handleDelete(c Call) Response {
	id := asString(c.Payload["identity"])
	o := d.find(id)
	if o == nil {
		return notFound(id)
	}
	o.Deleted = true
	return OK(map[string]any{"deleted": true, "verify": absentVerdict()})
}

func absentVerdict() map[string]any {
	return map[string]any{
		"found":     false,
		"type":      "Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException",
		"errorCode": 0x208D,
		"message":   "Cannot find an object with identity",
	}
}

// handleDeletedProbe answers the tombstone probe. It matches on the filter's
// sAMAccountName or lastKnownParent term rather than parsing RFC 4515, which
// is enough for the two filters this library builds.
func (d *Directory) handleDeletedProbe(c Call) Response {
	filter := asString(c.Payload["filter"])
	matches := []any{}
	for _, o := range d.objects {
		if !o.Deleted {
			continue
		}
		sam := asString(o.Data["samAccountName"])
		byParent := strings.Contains(filter, "lastKnownParent="+parentOf(o.DN)) &&
			strings.Contains(filter, "name="+asString(o.Data["name"]))
		bySAM := sam != "" && strings.Contains(filter, "sAMAccountName="+sam+")")
		if bySAM || byParent {
			matches = append(matches, map[string]any{
				"objectGUID":        o.GUID,
				"distinguishedName": o.DN + `\0ADEL:` + o.GUID + ",CN=Deleted Objects," + d.dnc,
				"lastKnownParent":   parentOf(o.DN),
			})
		}
	}
	return OK(map[string]any{"matches": matches})
}

// project returns a copy of the object's data, which is what a read sees.
func (d *Directory) project(o *DirectoryObject) map[string]any {
	out := make(map[string]any, len(o.Data))
	for k, v := range o.Data {
		out[k] = v
	}
	return out
}

// handleSearch answers a typed search: class filter, DN scope, the bounded LDAP
// evaluator, and the size cap the library requested (SizeLimit+1). Results are
// DN-ordered so truncation and assertions are deterministic.
func (d *Directory) handleSearch(c Call, class string) Response {
	filter := asString(c.Payload["filter"])
	base := asString(c.Payload["searchBase"])
	scope := asString(c.Payload["scope"])
	limit, _ := c.Payload["sizeLimit"].(float64) // JSON numbers decode as float64
	max := int(limit)

	matched := make([]*DirectoryObject, 0)
	for _, o := range d.objects {
		if o.Deleted || o.Class != class {
			continue
		}
		if !inScope(o.DN, base, scope) {
			continue
		}
		ok, err := matchFilter(o, filter)
		if err != nil {
			return Fail("Microsoft.ActiveDirectory.Management.ADFilterParsingException", err.Error(), 0)
		}
		if ok {
			matched = append(matched, o)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].DN < matched[j].DN })
	if max > 0 && len(matched) > max {
		matched = matched[:max]
	}
	results := make([]any, 0, len(matched))
	for _, o := range matched {
		results = append(results, d.project(o))
	}
	return OK(map[string]any{"results": results})
}

// inScope reports whether dn is within base at the given -SearchScope value.
func inScope(dn, base, scope string) bool {
	switch scope {
	case "Base":
		return strings.EqualFold(dn, base)
	case "OneLevel":
		return strings.EqualFold(parentOf(dn), base)
	default: // Subtree
		return strings.EqualFold(dn, base) ||
			strings.HasSuffix(strings.ToLower(dn), strings.ToLower(","+base))
	}
}

// parentOf splits a DN at the first unescaped comma. The library's own parser
// is internal, and the fake only ever sees DNs it built.
func parentOf(dn string) string {
	for i := 0; i < len(dn); i++ {
		if dn[i] == ',' && (i == 0 || dn[i-1] != '\\') {
			return dn[i+1:]
		}
	}
	return ""
}

// Seed inserts an object directly, for tests that need a pre-existing
// directory (brownfield import, data sources).
func (d *Directory) Seed(class, name, container string, data map[string]any) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	guid := d.nextGUID()
	dn := buildDN(class, name, container)
	obj := &DirectoryObject{GUID: guid, Class: class, DN: dn, Data: map[string]any{
		"objectGUID": guid, "distinguishedName": dn, "name": name,
	}}
	for k, v := range data {
		obj.Data[k] = v
	}
	d.objects[guid] = obj
	return guid
}

// memberGUIDs reads the member set stored on a group, tolerating either the
// []string the fake writes or the []any a decode round trip might yield.
func memberGUIDs(o *DirectoryObject) []string {
	switch t := o.Data["member"].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			out = append(out, asString(v))
		}
		return out
	}
	return nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, asString(e))
		}
		return out
	}
	return nil
}

func (d *Directory) handleMembersAdd(c Call) Response {
	g := d.find(asString(c.Payload["identity"]))
	if g == nil {
		return notFound(asString(c.Payload["identity"]))
	}
	set := map[string]bool{}
	for _, guid := range memberGUIDs(g) {
		set[guid] = true
	}
	for _, m := range toStringSlice(c.Payload["members"]) {
		mo := d.find(m)
		if mo == nil {
			return notFound(m)
		}
		set[mo.GUID] = true
	}
	g.Data["member"] = sortedKeys(set)
	return OK(map[string]any{"added": true, "guid": g.GUID})
}

func (d *Directory) handleMembersRemove(c Call) Response {
	g := d.find(asString(c.Payload["identity"]))
	if g == nil {
		return notFound(asString(c.Payload["identity"]))
	}
	set := map[string]bool{}
	for _, guid := range memberGUIDs(g) {
		set[guid] = true
	}
	for _, m := range toStringSlice(c.Payload["members"]) {
		mo := d.find(m)
		if mo == nil {
			// A deleted / nonexistent member: real AD surfaces not-found here and
			// the library swallows it on remove, so the edge counts as gone.
			return notFound(m)
		}
		delete(set, mo.GUID)
	}
	g.Data["member"] = sortedKeys(set)
	return OK(map[string]any{"removed": true, "guid": g.GUID})
}

func (d *Directory) handleMembersRead(c Call) Response {
	g := d.find(asString(c.Payload["identity"]))
	if g == nil {
		return notFound(asString(c.Payload["identity"]))
	}
	members := []any{}
	for _, guid := range memberGUIDs(g) {
		mo := d.objects[guid]
		if mo == nil || mo.Deleted {
			continue
		}
		members = append(members, map[string]any{
			"objectGUID":        mo.GUID,
			"distinguishedName": mo.DN,
			"objectClass":       mo.Class,
			"sid":               asString(mo.Data["sid"]),
		})
	}
	return OK(map[string]any{"members": members})
}

func (d *Directory) handleMemberCheck(c Call) Response {
	g := d.find(asString(c.Payload["group"]))
	if g == nil {
		return notFound(asString(c.Payload["group"]))
	}
	m := d.find(asString(c.Payload["member"]))
	if m == nil {
		// Member gone: the library's IsMember swallows not-found into "false".
		return notFound(asString(c.Payload["member"]))
	}
	for _, guid := range memberGUIDs(g) {
		if guid == m.GUID {
			return OK(map[string]any{"member": true})
		}
	}
	return OK(map[string]any{"member": false})
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fakeSchema answers the handful of names the fake-backed suites resolve. It is
// not the real schema — only what a consumer asks for is here.
var fakeSchema = map[string]string{
	"user":           "bf967aba-0de6-11d0-a285-00aa003049e2",
	"group":          "bf967a9c-0de6-11d0-a285-00aa003049e2",
	"member":         "bf9679c0-0de6-11d0-a285-00aa003049e2",
	"pwdLastSet":     "bf967a0a-0de6-11d0-a285-00aa003049e2",
	"Reset Password": "00299570-246d-11d0-a768-00aa006e0529",
}

func (d *Directory) handleSchemaResolve(c Call) Response {
	refs, _ := c.Payload["refs"].([]any)
	resolved := map[string]any{}
	for _, r := range refs {
		m, _ := r.(map[string]any)
		name := asString(m["name"])
		if g, ok := fakeSchema[name]; ok {
			resolved[name] = g
		} else {
			resolved[name] = nil
		}
	}
	return OK(map[string]any{"resolved": resolved})
}
