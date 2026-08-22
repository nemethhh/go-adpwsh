package adpwsh_test

import (
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

func TestDelegationTemplateAllTasks(t *testing.T) {
	type testCase struct {
		name          string
		task          adpwsh.DelegationTask
		expectedSpecs []adpwsh.ACESpec
	}

	tests := []testCase{
		{
			name: "TaskResetUserPasswords",
			task: adpwsh.TaskResetUserPasswords,
			expectedSpecs: []adpwsh.ACESpec{
				{
					Rights:      []adpwsh.Right{"ExtendedRight"},
					ObjectType:  "Reset Password",
					Scope:       adpwsh.InheritanceDescendants,
					ObjectClass: "user",
					Type:        adpwsh.ACEAllow,
				},
				{
					Rights:      []adpwsh.Right{"ReadProperty", "WriteProperty"},
					ObjectType:  "pwdLastSet",
					Scope:       adpwsh.InheritanceDescendants,
					ObjectClass: "user",
					Type:        adpwsh.ACEAllow,
				},
			},
		},
		{
			name: "TaskManageUsers",
			task: adpwsh.TaskManageUsers,
			expectedSpecs: []adpwsh.ACESpec{
				{
					Rights:      []adpwsh.Right{"CreateChild", "DeleteChild"},
					ObjectType:  "user",
					Scope:       adpwsh.InheritanceThis,
					ObjectClass: "",
					Type:        adpwsh.ACEAllow,
				},
				{
					Rights:      []adpwsh.Right{"GenericAll"},
					ObjectType:  "",
					Scope:       adpwsh.InheritanceDescendants,
					ObjectClass: "user",
					Type:        adpwsh.ACEAllow,
				},
			},
		},
		{
			name: "TaskModifyGroupMembership",
			task: adpwsh.TaskModifyGroupMembership,
			expectedSpecs: []adpwsh.ACESpec{
				{
					Rights:      []adpwsh.Right{"ReadProperty", "WriteProperty"},
					ObjectType:  "member",
					Scope:       adpwsh.InheritanceDescendants,
					ObjectClass: "group",
					Type:        adpwsh.ACEAllow,
				},
			},
		},
		{
			name: "TaskManageGroups",
			task: adpwsh.TaskManageGroups,
			expectedSpecs: []adpwsh.ACESpec{
				{
					Rights:      []adpwsh.Right{"CreateChild", "DeleteChild"},
					ObjectType:  "group",
					Scope:       adpwsh.InheritanceThis,
					ObjectClass: "",
					Type:        adpwsh.ACEAllow,
				},
				{
					Rights:      []adpwsh.Right{"GenericAll"},
					ObjectType:  "",
					Scope:       adpwsh.InheritanceDescendants,
					ObjectClass: "group",
					Type:        adpwsh.ACEAllow,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d adpwsh.DelegationClient
			specs, err := d.Template(tt.task)
			if err != nil {
				t.Fatalf("Template: %v", err)
			}

			if len(specs) != len(tt.expectedSpecs) {
				t.Fatalf("got %d specs, want %d", len(specs), len(tt.expectedSpecs))
			}

			for i, spec := range specs {
				expected := tt.expectedSpecs[i]

				if len(spec.Rights) != len(expected.Rights) {
					t.Errorf("spec[%d].Rights: got %d items, want %d", i, len(spec.Rights), len(expected.Rights))
				}
				for j, r := range spec.Rights {
					if r != expected.Rights[j] {
						t.Errorf("spec[%d].Rights[%d]: got %q, want %q", i, j, r, expected.Rights[j])
					}
				}

				if spec.ObjectType != expected.ObjectType {
					t.Errorf("spec[%d].ObjectType: got %q, want %q", i, spec.ObjectType, expected.ObjectType)
				}

				if spec.ObjectClass != expected.ObjectClass {
					t.Errorf("spec[%d].ObjectClass: got %q, want %q", i, spec.ObjectClass, expected.ObjectClass)
				}

				if spec.Scope != expected.Scope {
					t.Errorf("spec[%d].Scope: got %v, want %v", i, spec.Scope, expected.Scope)
				}

				if spec.Type != expected.Type {
					t.Errorf("spec[%d].Type: got %v, want %v", i, spec.Type, expected.Type)
				}
			}
		})
	}
}

func TestDelegationTemplateUnknownTask(t *testing.T) {
	var d adpwsh.DelegationClient
	if _, err := d.Template("bogus"); err == nil {
		t.Error("unknown task did not error")
	}
}

func TestTasksReturnsAllFourInOrder(t *testing.T) {
	tasks := adpwsh.Tasks()
	if len(tasks) != 4 {
		t.Fatalf("Tasks() returned %d items, want 4", len(tasks))
	}

	expectedOrder := []adpwsh.DelegationTask{
		adpwsh.TaskResetUserPasswords,
		adpwsh.TaskManageUsers,
		adpwsh.TaskModifyGroupMembership,
		adpwsh.TaskManageGroups,
	}

	for i, expected := range expectedOrder {
		if tasks[i] != expected {
			t.Errorf("Tasks()[%d]: got %q, want %q", i, tasks[i], expected)
		}
	}
}
