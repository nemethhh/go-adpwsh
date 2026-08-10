package adpwsh_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) Debug(_ context.Context, msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprint(append([]any{msg}, kv...)...))
}

func (l *recordingLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// Retrying an access-denied error only delays a clear message; retrying a
// server-busy error is the whole point. Both are asserted by call count.
func TestRetryOnlyOnTransient(t *testing.T) {
	tests := []struct {
		name      string
		exception string
		code      int
		wantCalls int
	}{
		{"transient is retried", "Microsoft.ActiveDirectory.Management.ADServerDownException", 0x06BA, 4},
		{"denied is not", "Microsoft.ActiveDirectory.Management.ADException", 0x0005, 1},
		{"unknown is not", "Some.Other.Exception", 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			tr := fake.New(func(c fake.Call) fake.Response {
				if c.Op == "rootdse" {
					return fake.OK(rootDSE())
				}
				calls++
				return fake.Fail(tt.exception, "boom", tt.code)
			})
			client := mustClient(t, adpwsh.Config{
				Transport: tr,
				Retry: adpwsh.RetryConfig{
					MaxAttempts:    4,
					InitialBackoff: time.Millisecond,
					MaxBackoff:     2 * time.Millisecond,
				},
			})
			_, err := client.OU.Get(context.Background(), adpwsh.ByGUID("9f2c"))
			if err == nil {
				t.Fatal("expected an error")
			}
			if calls != tt.wantCalls {
				t.Errorf("transport called %d times, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestRetryRecoversAfterTransient(t *testing.T) {
	calls := 0
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		calls++
		if calls < 3 {
			return fake.Fail("Microsoft.ActiveDirectory.Management.ADServerDownException", "busy", 0x200E)
		}
		return fake.OK(map[string]any{
			"objectGUID": "9f2c", "distinguishedName": "OU=Staff,DC=corp,DC=local",
			"name": "Staff", "description": "", "protected": true,
		})
	})
	client := mustClient(t, adpwsh.Config{
		Transport: tr,
		Retry:     adpwsh.RetryConfig{MaxAttempts: 4, InitialBackoff: time.Millisecond},
	})
	ou, err := client.OU.Get(context.Background(), adpwsh.ByGUID("9f2c"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ou.Name != "Staff" || calls != 3 {
		t.Errorf("ou = %+v after %d calls", ou, calls)
	}
}

// Every operation carries the pinned DC and, when configured, the credential.
func TestExecInjectsServerAndCredential(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op != "rootdse" {
			if c.Payload["server"] != "dc01.corp.local" {
				t.Errorf("op %q missing the pinned server: %v", c.Op, c.Payload["server"])
			}
			cred, ok := c.Payload["credential"].(map[string]any)
			if !ok || cred["username"] != "CORP\\svc_tf" || cred["password"] != "hunter2" {
				t.Errorf("credential not delivered: %v", c.Payload["credential"])
			}
		}
		return fake.OK(rootDSE())
	})
	client := mustClient(t, adpwsh.Config{
		Transport:  tr,
		Server:     "dc01.corp.local",
		Credential: &adpwsh.Credential{Username: `CORP\svc_tf`, Password: adpwsh.NewSecret("hunter2")},
	})
	_, _ = client.OU.Get(context.Background(), adpwsh.ByGUID("9f2c"))
}

// #197 leaked a credential into an error message. The payload is masked before
// the log line is constructed, so there is no window in which it is present.
func TestLoggerNeverSeesASecret(t *testing.T) {
	log := &recordingLogger{}
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	_ = mustClient(t, adpwsh.Config{
		Transport:  tr,
		Log:        log,
		Credential: &adpwsh.Credential{Username: "svc_tf", Password: adpwsh.NewSecret("hunter2-do-not-leak")},
	})
	if out := log.all(); strings.Contains(out, "hunter2-do-not-leak") {
		t.Fatalf("the log contains the password:\n%s", out)
	}
	if out := log.all(); !strings.Contains(out, "REDACTED") {
		t.Errorf("expected a REDACTED marker in the log:\n%s", out)
	}
}

func TestContextCancellationIsNotRetried(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		cancel()
		return fake.Response{RunErr: context.Canceled}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	_, err := client.OU.Get(ctx, adpwsh.ByGUID("9f2c"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the context error to survive, got %v", err)
	}
}

func mustClient(t *testing.T, cfg adpwsh.Config) *adpwsh.Client {
	t.Helper()
	c, err := adpwsh.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}
