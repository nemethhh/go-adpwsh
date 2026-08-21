package adscript

// Op names. Script accepts only these, so there is no path by which a caller
// supplies script text.
const (
	OpRootDSE         = "rootdse"
	OpDCList          = "dclist"
	OpDeletedProbe    = "deleted_probe"
	OpReplicate       = "replicate"
	OpReplicateVerify = "replicate_verify"
	OpOUCreate        = "ou_create"
	OpOURead          = "ou_read"
	OpOUUpdate        = "ou_update"
	OpOUDelete        = "ou_delete"
	OpGroupCreate     = "group_create"
	OpGroupRead       = "group_read"
	OpGroupUpdate     = "group_update"
	OpGroupDelete     = "group_delete"

	OpGroupMembersRead   = "group_members_read"
	OpGroupMembersAdd    = "group_members_add"
	OpGroupMembersRemove = "group_members_remove"
	OpGroupMemberCheck   = "group_member_check"

	OpUserCreate      = "user_create"
	OpUserRead        = "user_read"
	OpUserUpdate      = "user_update"
	OpUserDelete      = "user_delete"
	OpUserSetPassword = "user_setpassword"
)

var ops = []string{
	OpRootDSE, OpDCList, OpDeletedProbe, OpReplicate, OpReplicateVerify,
	OpOUCreate, OpOURead, OpOUUpdate, OpOUDelete,
	OpGroupCreate, OpGroupRead, OpGroupUpdate, OpGroupDelete,
	OpGroupMembersRead, OpGroupMembersAdd, OpGroupMembersRemove, OpGroupMemberCheck,
	OpUserCreate, OpUserRead, OpUserUpdate, OpUserDelete, OpUserSetPassword,
}

// Ops returns every op name, in a stable order.
func Ops() []string {
	out := make([]string, len(ops))
	copy(out, ops)
	return out
}

// Tool script names. A tool is build-time utility PowerShell — the schema
// exporter is the only one — and tools are deliberately a second closed set:
// Script accepts only ops, ToolScript accepts only tools, and neither accepts
// script text. Keeping them apart is what lets a tool run a query the library's
// operation set does not expose without widening that set, which is a
// correctness property: no caller can make the library run arbitrary directory
// code.
const (
	ToolSchemaFetch = "schema_fetch"
)

var tools = []string{ToolSchemaFetch}

// Tools returns every tool script name, in a stable order.
func Tools() []string {
	out := make([]string, len(tools))
	copy(out, tools)
	return out
}
