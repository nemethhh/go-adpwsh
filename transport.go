package adpwsh

import "context"

// Result is the raw outcome of one pwsh invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Transport runs one PowerShell command on the jump box.
//
// Implementations must invoke:
//
//	<pwsh> -NoProfile -NonInteractive -EncodedCommand <encodedCommand>
//
// with payload written to the process's standard input and closed, and must
// return its stdout, stderr and exit code verbatim.
//
// Run returns a non-nil error only when the process could not be run to
// completion — dial, authentication, channel exhaustion, context cancellation.
// A non-zero exit is reported through Result.ExitCode, never as an error: the
// distinction between "AD said no" and "we could not reach AD" is decided
// above this interface, not inside it. An implementation that can classify its
// own failure should return an *Error with the appropriate Kind (KindTransient
// for an exhausted channel, KindTransport for a dial or auth failure); any
// other error is treated as KindTransport.
type Transport interface {
	Run(ctx context.Context, encodedCommand string, payload []byte) (Result, error)
	Close() error
}
