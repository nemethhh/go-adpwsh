package adpwsh_test

import (
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func TestDelegationTemplateResetPasswords(t *testing.T) {
	var d adpwsh.DelegationClient
	specs, err := d.Template(adpwsh.TaskResetUserPasswords)
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("reset_user_passwords -> %d specs, want 2", len(specs))
	}
	// First spec: the Reset Password extended right on descendant users.
	s := specs[0]
	if s.ObjectType != "Reset Password" || s.ObjectClass != "user" ||
		s.Scope != adpwsh.InheritanceDescendants || len(s.Rights) != 1 || s.Rights[0] != "ExtendedRight" {
		t.Errorf("spec[0] = %+v", s)
	}
}

func TestDelegationTemplateUnknownTask(t *testing.T) {
	var d adpwsh.DelegationClient
	if _, err := d.Template("bogus"); err == nil {
		t.Error("unknown task did not error")
	}
}

func TestTasksListsAllFour(t *testing.T) {
	if len(adpwsh.Tasks()) != 4 {
		t.Errorf("Tasks() = %v", adpwsh.Tasks())
	}
}
