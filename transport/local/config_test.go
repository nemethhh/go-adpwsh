package local_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adlocal "github.com/nemethhh/go-adpwsh/transport/local"
)

func TestConfigDefaults(t *testing.T) {
	got := adlocal.Config{}.WithDefaults()
	if got.PwshPath != "pwsh" {
		t.Errorf("PwshPath = %q, want pwsh", got.PwshPath)
	}
	// Four, not ten: every operation is a real process paying a fresh
	// Import-Module ActiveDirectory, and Terraform's default parallelism is 10.
	if got.Concurrency != 4 {
		t.Errorf("Concurrency = %d, want 4", got.Concurrency)
	}
	if got.Timeout != 60*time.Second {
		t.Errorf("Timeout = %s, want 60s", got.Timeout)
	}
	// An empty WorkingDir means the caller's own directory. Inventing one here
	// would silently move where relative paths resolve.
	if got.WorkingDir != "" {
		t.Errorf("WorkingDir = %q, want empty", got.WorkingDir)
	}
}

func TestConfigDefaultsDoNotOverrideValues(t *testing.T) {
	cfg := adlocal.Config{
		PwshPath:    "/opt/microsoft/powershell/7/pwsh",
		Concurrency: 1,
		Timeout:     5 * time.Second,
		WorkingDir:  os.TempDir(),
	}
	if got := cfg.WithDefaults(); got != cfg {
		t.Errorf("WithDefaults changed a value that was already set: %+v", got)
	}
}

func TestConfigValidate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     adlocal.Config
		wantErr string
	}{
		{"the zero value is valid", adlocal.Config{}, ""},
		{"negative concurrency", adlocal.Config{Concurrency: -1}, "concurrency"},
		{"negative timeout", adlocal.Config{Timeout: -time.Second}, "timeout"},
		{"a working directory that exists", adlocal.Config{WorkingDir: dir}, ""},
		{"a working directory that is a file", adlocal.Config{WorkingDir: file}, "not a directory"},
		{"a working directory that is absent", adlocal.Config{WorkingDir: filepath.Join(dir, "gone")}, "working_dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tt.wantErr)
			}
		})
	}
}
