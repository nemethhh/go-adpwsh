// Package fake provides a Transport double: it synthesizes result envelopes,
// injects AD exceptions, and records what was asked of it. Together with
// Directory it makes the whole library — and any consumer built on it —
// testable with no Windows VM.
package fake

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// Call is one recorded invocation.
type Call struct {
	Op      string
	Payload map[string]any
	Script  string // the PowerShell that would actually have run
}

// ScriptError is the error half of a synthesized envelope.
type ScriptError struct {
	Type               string `json:"type"`
	Message            string `json:"message"`
	Category           string `json:"category"`
	TargetName         string `json:"targetName"`
	FQID               string `json:"fqid"`
	ErrorCode          *int   `json:"errorCode"`
	ServerErrorMessage string `json:"serverErrorMessage"`
}

// Response is what a handler returns. Data and Err synthesize an envelope;
// Stdout, Stderr and ExitCode override it entirely, which is how the
// malformed-output paths are tested. RunErr makes Run itself fail, which is
// how a dial or channel failure is simulated.
type Response struct {
	Data     any
	Err      *ScriptError
	Stdout   string
	Stderr   string
	ExitCode int
	RunErr   error
}

// OK returns a success envelope carrying data.
func OK(data any) Response { return Response{Data: data} }

// Fail returns an AD refusal. Pass code 0 for an exception with no ErrorCode.
func Fail(exceptionType, message string, code int) Response {
	e := &ScriptError{Type: exceptionType, Message: message, ServerErrorMessage: message}
	if code != 0 {
		c := code
		e.ErrorCode = &c
	}
	return Response{Err: e}
}

// Raw returns process output verbatim, bypassing envelope synthesis.
func Raw(stdout, stderr string, exitCode int) Response {
	return Response{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}
}

// Transport is a programmable adpwsh.Transport.
type Transport struct {
	handler func(Call) Response

	mu     sync.Mutex
	calls  []Call
	closed bool
}

// New returns a Transport that routes every Run through handler.
func New(handler func(Call) Response) *Transport {
	return &Transport{handler: handler}
}

func (t *Transport) Run(ctx context.Context, encodedCommand string, payload []byte) (adpwsh.Result, error) {
	if err := ctx.Err(); err != nil {
		return adpwsh.Result{}, err
	}
	script, err := adscript.DecodeCommand(encodedCommand)
	if err != nil {
		return adpwsh.Result{}, fmt.Errorf("fake: %w", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return adpwsh.Result{}, fmt.Errorf("fake: cannot decode payload: %w", err)
	}
	op, _ := decoded["op"].(string)
	call := Call{Op: op, Payload: decoded, Script: script}

	t.mu.Lock()
	t.calls = append(t.calls, call)
	t.mu.Unlock()

	resp := t.handler(call)
	if resp.RunErr != nil {
		return adpwsh.Result{}, resp.RunErr
	}
	if resp.Stdout != "" || resp.Stderr != "" || resp.ExitCode != 0 {
		return adpwsh.Result{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode}, nil
	}

	body := map[string]any{"ok": resp.Err == nil}
	if resp.Err != nil {
		body["error"] = resp.Err
	} else {
		body["data"] = resp.Data
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return adpwsh.Result{}, fmt.Errorf("fake: cannot encode envelope: %w", err)
	}
	return adpwsh.Result{
		Stdout: "<<<TFAD:BEGIN>>>\r\n" + string(encoded) + "\r\n<<<TFAD:END>>>\r\n",
	}, nil
}

func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// Closed reports whether Close was called, so a test can assert the client
// releases its transport.
func (t *Transport) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// Calls returns a copy of everything asked of this transport, in order.
func (t *Transport) Calls() []Call {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Call, len(t.calls))
	copy(out, t.calls)
	return out
}

// LastCall returns the most recent call, or the zero Call.
func (t *Transport) LastCall() Call {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.calls) == 0 {
		return Call{}
	}
	return t.calls[len(t.calls)-1]
}

// Reset drops the recorded calls.
func (t *Transport) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls = nil
}

var _ adpwsh.Transport = (*Transport)(nil)
