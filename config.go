package adpwsh

import (
	"context"
	"time"
)

// Config configures a Client. Transport is the only required field.
type Config struct {
	// Transport is how PowerShell reaches the jump box. Required.
	Transport Transport

	// Server pins the domain controller every cmdlet targets. When empty it is
	// discovered once in New and never changes for this client's lifetime.
	Server string

	// Credential, when set, becomes the -Credential passed to every cmdlet on
	// the jump box. Omit it to use the transport session's own identity.
	Credential *Credential

	// Retry governs re-attempts, and applies only to errors classified
	// transient.
	Retry RetryConfig

	// Replication governs the post-write wait.
	Replication ReplicationConfig

	// Log is an optional output port. It is not an extension seam: redaction
	// cannot be the caller's job, because the caller never sees the payload.
	// The library masks credential-bearing keys before anything reaches Log.
	Log Logger
}

// Credential is a username and password for the AD cmdlets.
type Credential struct {
	Username string
	Password Secret
}

// Logger is the output port. A three-line adapter satisfies it from tflog,
// which is how the provider gets logging without this module importing
// anything from Terraform.
type Logger interface {
	Debug(ctx context.Context, msg string, kv ...any)
}

// RetryConfig is values, not code.
type RetryConfig struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Jitter         float64 // fraction of the backoff, 0..1
}

func (r RetryConfig) withDefaults() RetryConfig {
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = 4
	}
	if r.InitialBackoff <= 0 {
		r.InitialBackoff = 250 * time.Millisecond
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = 5 * time.Second
	}
	if r.Jitter < 0 || r.Jitter > 1 {
		r.Jitter = 0.2
	}
	return r
}

// ReplicationConfig governs the wait that follows a write. Replication is a
// property of domain topology, not of any single object, so it is configured
// once on the client.
type ReplicationConfig struct {
	Wait         bool
	Targets      []string // DC host names, or the single element "all"
	ForceSync    bool
	Timeout      time.Duration
	PollInterval time.Duration
}

func (r ReplicationConfig) withDefaults() ReplicationConfig {
	if r.Timeout <= 0 {
		r.Timeout = 60 * time.Second
	}
	if r.PollInterval <= 0 {
		r.PollInterval = 2 * time.Second
	}
	return r
}
