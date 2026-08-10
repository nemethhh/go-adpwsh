package adpwsh_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoTerraformDependency is the mechanical enforcement of the module
// boundary. go-adpwsh is a separate repository only because it is useful
// without Terraform; without this gate the boundary erodes at the first
// convenient diag.Diagnostics return. Test imports are included because a
// Terraform dependency that enters through a test still makes the claim false.
func TestNoTerraformDependency(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps -test ./...: %v\n%s", err, out)
	}
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(pkg, "terraform") || strings.Contains(pkg, "hashicorp") {
			t.Errorf("forbidden dependency in module boundary: %s", pkg)
		}
	}
}
