package adpwsh_test

import (
	"context"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adcore/adcoretest"
	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

// The PowerShell backend must satisfy every guarantee adcore states, asserted
// behaviourally rather than by construction.
func TestPwshDirectoryConformance(t *testing.T) {
	adcoretest.RunDirectorySuite(t, func(t *testing.T) adcore.Directory {
		dir := fake.NewDirectory()
		client, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: dir.Transport()})
		if err != nil {
			t.Fatalf("adpwsh.New: %v", err)
		}
		return client.Directory()
	})
}
