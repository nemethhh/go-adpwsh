package adschema

import (
	"context"
	"errors"
	"strings"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

// fetchFixture is a two-attribute, two-class schema in the shape the fetch
// script emits.
func fetchFixture() map[string]any {
	return map[string]any{
		"source": map[string]any{
			"domain":        "corp.local",
			"forestMode":    "Windows2025Forest",
			"schemaNC":      "CN=Schema,CN=Configuration,DC=corp,DC=local",
			"objectVersion": 91,
		},
		"attributes": []any{
			map[string]any{
				"name": "cn", "oid": "2.5.4.3", "syntax": "2.5.5.12", "omSyntax": 64,
				"singleValued": true, "systemOnly": false, "rangeLower": nil,
				"rangeUpper": 64, "searchFlags": 13, "linkId": nil,
			},
			map[string]any{
				"name": "member", "oid": "1.2.840.113556.1.4.31", "syntax": "2.5.5.1",
				"omSyntax": 127, "singleValued": false, "systemOnly": false,
				"rangeLower": nil, "rangeUpper": nil, "searchFlags": 0, "linkId": 2,
			},
		},
		"classes": []any{
			map[string]any{
				"name": "top", "category": 2, "subClassOf": "top",
				"auxiliaryClass": []any{}, "systemAuxiliaryClass": []any{},
				"mayContain": []any{}, "systemMayContain": []any{},
				"mustContain": []any{}, "systemMustContain": []any{"cn"},
			},
			map[string]any{
				"name": "group", "category": 1, "subClassOf": "top",
				"auxiliaryClass": []any{}, "systemAuxiliaryClass": []any{},
				"mayContain": []any{"member"}, "systemMayContain": []any{},
				"mustContain": []any{}, "systemMustContain": []any{},
			},
		},
	}
}

func TestFetchDecodesTheSchema(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(fetchFixture()) })
	raw, err := Fetch(context.Background(), tr, FetchOptions{Server: "dc01.corp.local"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Source.ObjectVersion != 91 || raw.Source.Domain != "corp.local" {
		t.Errorf("source = %+v", raw.Source)
	}
	if len(raw.Attributes) != 2 || len(raw.Classes) != 2 {
		t.Fatalf("got %d attributes and %d classes", len(raw.Attributes), len(raw.Classes))
	}
	cn := raw.Attributes[0]
	if cn.Name != "cn" || cn.SearchFlags != 13 || cn.RangeLower != nil {
		t.Errorf("cn = %+v", cn)
	}
	if cn.RangeUpper == nil || *cn.RangeUpper != 64 {
		t.Errorf("cn rangeUpper = %v", cn.RangeUpper)
	}
	if raw.Classes[1].SubClassOf != "top" || len(raw.Classes[1].MayContain) != 1 {
		t.Errorf("group = %+v", raw.Classes[1])
	}
}

// The script is a constant and every value travels as JSON on stdin. The
// payload carries the pinned server and the credential and nothing else — the
// class selection happens in Go, so no caller input reaches the script at all.
func TestFetchRunsTheConstantToolScript(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(fetchFixture()) })
	_, err := Fetch(context.Background(), tr, FetchOptions{
		Server:     "dc01.corp.local",
		Credential: &Credential{Username: "CORP\\svc", Password: "pw"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	call := tr.LastCall()
	want, err := adscript.ToolScript(adscript.ToolSchemaFetch)
	if err != nil {
		t.Fatal(err)
	}
	if call.Script != want {
		t.Error("Fetch must run exactly the composed tool script")
	}
	if call.Op != adscript.ToolSchemaFetch {
		t.Errorf("payload op = %q", call.Op)
	}
	if call.Payload["server"] != "dc01.corp.local" {
		t.Errorf("payload server = %v", call.Payload["server"])
	}
	cred, ok := call.Payload["credential"].(map[string]any)
	if !ok || cred["username"] != "CORP\\svc" || cred["password"] != "pw" {
		t.Errorf("payload credential = %v", call.Payload["credential"])
	}
	for _, key := range []string{"classes", "schemaNC", "filter"} {
		if _, present := call.Payload[key]; present {
			t.Errorf("payload must not carry %q; the script needs no caller input", key)
		}
	}
}

// Error handling follows the library's classification rather than inventing its
// own: a refused read of the schema naming context is KindDenied and names the
// container AD refused.
func TestFetchClassifiesADenial(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		resp := fake.Fail("System.UnauthorizedAccessException", "Access is denied", 0x0005)
		resp.Err.TargetName = "CN=Schema,CN=Configuration,DC=corp,DC=local"
		return resp
	})
	_, err := Fetch(context.Background(), tr, FetchOptions{})
	if !errors.Is(err, adpwsh.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	var e *adpwsh.Error
	if !errors.As(err, &e) || !strings.Contains(e.Target, "CN=Schema") {
		t.Errorf("the error must name the container: %+v", e)
	}
}

func TestFetchTreatsAMissingEnvelopeAsTransport(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Raw("", "Import-Module : the module was not found", 1)
	})
	if _, err := Fetch(context.Background(), tr, FetchOptions{}); !errors.Is(err, adpwsh.ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

// A transport that classified its own failure keeps its Kind. Flattening a
// retryable channel exhaustion into a non-retryable transport error is the
// regression this pins.
//
// errors.Is alone cannot pin this: a re-wrap that discards the branch still
// nests the original *Error as the wrapper's Err, and errors.Is keeps
// unwrapping until it finds a match anywhere in the chain — so it would
// report ErrTransient present even after the regression. What a retry loop
// actually consults is errors.As's first match, which is the outermost
// *Error, so the assertions below check that one's Kind and Op directly.
func TestFetchKeepsATransportsOwnKind(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Response{RunErr: &adpwsh.Error{
			Kind: adpwsh.KindTransient, Op: "ssh.Run",
			Err: errors.New("cannot open a session channel"),
		}}
	})
	_, err := Fetch(context.Background(), tr, FetchOptions{})
	var e *adpwsh.Error
	if !errors.As(err, &e) {
		t.Fatalf("want an *adpwsh.Error, got %v", err)
	}
	if e.Kind != adpwsh.KindTransient {
		t.Errorf("Kind = %v, want KindTransient", e.Kind)
	}
	if e.Op != "ssh.Run" {
		t.Errorf("Op = %q; Fetch must return the transport's own *Error unchanged, not re-wrap it", e.Op)
	}
}

// The other half of the same branch: a run error the transport did not
// classify at all — a bare dial failure, say — still becomes KindTransport,
// same as every other unclassified transport failure.
func TestFetchClassifiesAnUnclassifiedRunErrorAsTransport(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Response{RunErr: errors.New("dial tcp 10.0.0.1:22: connect: connection refused")}
	})
	if _, err := Fetch(context.Background(), tr, FetchOptions{}); !errors.Is(err, adpwsh.ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
}

// An empty collection is the partial fetch that a retry loop would paper over,
// so it is fatal and says what it saw.
func TestFetchRejectsAnEmptyResult(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		f := fetchFixture()
		f["classes"] = []any{}
		return fake.OK(f)
	})
	_, err := Fetch(context.Background(), tr, FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "0 classes") {
		t.Fatalf("want a partial-fetch error naming the counts, got %v", err)
	}
}
