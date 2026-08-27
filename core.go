package adpwsh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

type core struct {
	tr     Transport
	server string
	dnc    string
	cred   *Credential
	retry  RetryConfig
	repl   ReplicationConfig
	log    Logger
	locks  *keyedMutex
}

// exec runs one operation: it injects the pinned server and the credential,
// serializes the payload, logs a masked copy, retries while the error is
// transient, parses the envelope, and decodes the data into out.
func (c *core) exec(ctx context.Context, op string, payload map[string]any, out any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["op"] = op
	if isACLOp(op) {
		if cr, ok := c.tr.(interface{ Constrained() bool }); ok && cr.Constrained() {
			return &Error{Kind: KindUnsupported, Op: op, Err: errors.New(
				`ACL delegation requires a full-language endpoint; set the winrm transport's language_mode to "full" (or manage the delegation out-of-band)`)}
		}
	}
	if c.server != "" {
		payload["server"] = c.server
	}
	if c.cred != nil {
		payload["credential"] = map[string]any{
			"username": c.cred.Username,
			"password": c.cred.Password.reveal(),
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		// A Secret that reached the payload by a struct walk lands here, which
		// is exactly the loud failure its MarshalJSON exists to produce.
		return &Error{Kind: KindUnknown, Op: op, Err: fmt.Errorf("cannot encode payload: %w", err)}
	}

	script, err := adscript.Script(op)
	if err != nil {
		return &Error{Kind: KindUnknown, Op: op, Err: err}
	}
	encoded := adscript.EncodeCommand(script)

	c.debug(ctx, "adpwsh: running operation", "op", op, "server", c.server, "payload", maskPayload(payload))

	var lastErr error
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		res, runErr := c.tr.Run(ctx, encoded, body)
		var data json.RawMessage
		if runErr != nil {
			lastErr = asError(op, runErr)
		} else {
			data, lastErr = ParseEnvelope(op, res)
		}
		if lastErr == nil {
			if out == nil || len(data) == 0 {
				return nil
			}
			if err := json.Unmarshal(data, out); err != nil {
				return &Error{Kind: KindTransport, Op: op, Err: fmt.Errorf("cannot decode %s data: %w", op, err)}
			}
			return nil
		}
		var e *Error
		if !asAdpwshError(lastErr, &e) || !e.Kind.retryable() || attempt == c.retry.MaxAttempts {
			return lastErr
		}
		c.debug(ctx, "adpwsh: retrying transient failure", "op", op, "attempt", attempt, "error", lastErr.Error())
		if err := c.backoff(ctx, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

// isACLOp reports whether op is one of the ACL delegation ops, whose
// implementation on the jump box calls into .NET DirectoryServices ACL
// classes that a ConstrainedLanguage endpoint cannot construct.
func isACLOp(op string) bool {
	return op == adscript.OpACLRead || op == adscript.OpACLGrant || op == adscript.OpACLRevoke
}

// backoff sleeps for the attempt's exponential delay, jittered, and honours
// cancellation.
func (c *core) backoff(ctx context.Context, attempt int) error {
	d := c.retry.InitialBackoff << (attempt - 1)
	if d > c.retry.MaxBackoff {
		d = c.retry.MaxBackoff
	}
	if c.retry.Jitter > 0 {
		spread := float64(d) * c.retry.Jitter
		d = time.Duration(float64(d) - spread + rand.Float64()*2*spread)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return &Error{Kind: KindTransport, Err: ctx.Err()}
	case <-t.C:
		return nil
	}
}

func (c *core) debug(ctx context.Context, msg string, kv ...any) {
	if c.log == nil {
		return
	}
	c.log.Debug(ctx, msg, kv...)
}

// maskedKeys are payload keys whose values never reach a log line. Masking
// happens here rather than at the output port because the port's implementer
// never sees the payload and so cannot mask it.
var maskedKeys = map[string]bool{
	"password":        true,
	"accountpassword": true,
	"newpassword":     true,
	"oldpassword":     true,
	"credential":      true,
}

func maskPayload(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if maskedKeys[strings.ToLower(k)] {
				out[k] = "REDACTED"
				continue
			}
			out[k] = maskPayload(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = maskPayload(val)
		}
		return out
	default:
		return v
	}
}

// asError normalizes a transport error. A transport that classified its own
// failure keeps its Kind; anything else is a transport failure.
func asError(op string, err error) error {
	var e *Error
	if asAdpwshError(err, &e) {
		if e.Op == "" {
			e.Op = op
		}
		return e
	}
	return &Error{Kind: KindTransport, Op: op, Err: err}
}

func asAdpwshError(err error, out **Error) bool { return errors.As(err, out) }

type deletedMatch struct {
	GUID            string `json:"objectGUID"`
	DN              string `json:"distinguishedName"`
	LastKnownParent string `json:"lastKnownParent"`
}

// probeDeleted searches the Deleted Objects container. With the Recycle Bin
// enabled a deleted object keeps its sAMAccountName and blocks re-creation
// with an opaque error; correctness rule 8 turns that into a named condition.
// filter must already be RFC 4515 escaped by the caller.
func (c *core) probeDeleted(ctx context.Context, filter string) ([]deletedMatch, error) {
	var out struct {
		Matches []deletedMatch `json:"matches"`
	}
	err := c.exec(ctx, adscript.OpDeletedProbe, map[string]any{
		"filter":     filter,
		"searchBase": c.dnc,
	}, &out)
	if err != nil {
		return nil, err
	}
	return out.Matches, nil
}

// annotateAlreadyExists upgrades an already-exists error with the deleted
// object that caused it, when there is one. A probe failure is swallowed: the
// original error is the one the caller needs, and the annotation is a courtesy.
func (c *core) annotateAlreadyExists(ctx context.Context, err error, filter string) error {
	var e *Error
	if !asAdpwshError(err, &e) || e.Kind != KindAlreadyExists {
		return err
	}
	matches, probeErr := c.probeDeleted(ctx, filter)
	if probeErr != nil || len(matches) == 0 {
		return err
	}
	e.Tombstoned = true
	e.Target = matches[0].DN
	return e
}
