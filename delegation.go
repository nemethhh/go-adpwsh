package adpwsh

import "fmt"

// DelegationClient expands a curated delegation task into the concrete ACEs that
// implement it. It performs no directory I/O: the expansion is pure, so a
// consumer can compute a plan from it without a round trip. Object types are
// friendly names; the caller resolves them to GUIDs.
type DelegationClient struct{}

// Tasks returns every task name, in a stable order.
func Tasks() []DelegationTask {
	return []DelegationTask{
		TaskResetUserPasswords, TaskManageUsers, TaskModifyGroupMembership, TaskManageGroups,
	}
}

// Template returns the ACE specs a task expands into. These mirror the AD
// "Delegate Control" wizard's common tasks; the object/attribute names are
// cross-checked against the schema well-known table and verified end-to-end on
// the lab.
func (d *DelegationClient) Template(task DelegationTask) ([]ACESpec, error) {
	switch task {
	case TaskResetUserPasswords:
		return []ACESpec{
			{Rights: []Right{"ExtendedRight"}, ObjectType: "Reset Password", Scope: InheritanceDescendants, ObjectClass: "user", Type: ACEAllow},
			{Rights: []Right{"ReadProperty", "WriteProperty"}, ObjectType: "pwdLastSet", Scope: InheritanceDescendants, ObjectClass: "user", Type: ACEAllow},
		}, nil
	case TaskManageUsers:
		return []ACESpec{
			{Rights: []Right{"CreateChild", "DeleteChild"}, ObjectType: "user", Scope: InheritanceThis, ObjectClass: "", Type: ACEAllow},
			{Rights: []Right{"GenericAll"}, ObjectType: "", Scope: InheritanceDescendants, ObjectClass: "user", Type: ACEAllow},
		}, nil
	case TaskModifyGroupMembership:
		return []ACESpec{
			{Rights: []Right{"ReadProperty", "WriteProperty"}, ObjectType: "member", Scope: InheritanceDescendants, ObjectClass: "group", Type: ACEAllow},
		}, nil
	case TaskManageGroups:
		return []ACESpec{
			{Rights: []Right{"CreateChild", "DeleteChild"}, ObjectType: "group", Scope: InheritanceThis, ObjectClass: "", Type: ACEAllow},
			{Rights: []Right{"GenericAll"}, ObjectType: "", Scope: InheritanceDescendants, ObjectClass: "group", Type: ACEAllow},
		}, nil
	default:
		return nil, fmt.Errorf("adpwsh: unknown delegation task %q", task)
	}
}
