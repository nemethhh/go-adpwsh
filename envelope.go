package adpwsh

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	sentinelBegin = "<<<TFAD:BEGIN>>>"
	sentinelEnd   = "<<<TFAD:END>>>"
)

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *envelopeError  `json:"error"`
}

type envelopeError struct {
	Type               string `json:"type"`
	Message            string `json:"message"`
	Category           string `json:"category"`
	TargetName         string `json:"targetName"`
	FQID               string `json:"fqid"`
	ErrorCode          *int   `json:"errorCode"`
	ServerErrorMessage string `json:"serverErrorMessage"`
}

// ParseEnvelope turns one raw Result into either the operation's data or a
// classified *Error. A non-zero exit or a missing envelope is KindTransport:
// the script exits 0 even when AD refuses, so anything else means the
// transport or the pwsh process itself failed.
//
// It is exported for the build-time tooling in this module that needs a query
// the op set does not expose — cmd/adschema — so that such a tool inherits
// this library's error classification instead of inventing its own. It
// confers no ability to run script text: the caller must already hold a
// Result.
func ParseEnvelope(op string, r Result) (json.RawMessage, error) {
	if r.ExitCode != 0 {
		return nil, &Error{
			Kind: KindTransport,
			Op:   op,
			Err:  fmt.Errorf("pwsh exited %d: %s", r.ExitCode, strings.TrimSpace(r.Stderr)),
		}
	}

	begin := strings.Index(r.Stdout, sentinelBegin)
	end := strings.Index(r.Stdout, sentinelEnd)
	if begin < 0 || end < 0 || end < begin {
		return nil, &Error{
			Kind: KindTransport,
			Op:   op,
			Err: fmt.Errorf("no result envelope in output (stdout %q, stderr %q)",
				truncate(r.Stdout, 512), truncate(strings.TrimSpace(r.Stderr), 512)),
		}
	}
	body := strings.TrimSpace(r.Stdout[begin+len(sentinelBegin) : end])

	var e envelope
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		return nil, &Error{
			Kind: KindTransport,
			Op:   op,
			Err:  fmt.Errorf("cannot decode result envelope: %w (body %q)", err, truncate(body, 512)),
		}
	}
	if e.OK {
		return e.Data, nil
	}
	if e.Error == nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: errors.New("envelope reported failure with no error detail")}
	}

	code := 0
	if e.Error.ErrorCode != nil {
		code = *e.Error.ErrorCode
	}
	msg := e.Error.ServerErrorMessage
	if msg == "" {
		msg = e.Error.Message
	}
	return nil, &Error{
		Kind:          Classify(e.Error.Type, code),
		Op:            op,
		ExceptionType: e.Error.Type,
		Code:          code,
		ServerMessage: msg,
		FQID:          e.Error.FQID,
		Target:        e.Error.TargetName,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
