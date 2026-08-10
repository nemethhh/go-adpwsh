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
	OpUserCreate, OpUserRead, OpUserUpdate, OpUserDelete, OpUserSetPassword,
}

// Ops returns every op name, in a stable order.
func Ops() []string {
	out := make([]string, len(ops))
	copy(out, ops)
	return out
}
