package adpwsh

import (
	"errors"
	"strings"
	"testing"
)

func env(body string) string {
	return "<<<TFAD:BEGIN>>>\n" + body + "\n<<<TFAD:END>>>\n"
}

func TestParseEnvelopeSuccess(t *testing.T) {
	raw, err := parseEnvelope("OU.Get", Result{Stdout: env(`{"ok":true,"data":{"name":"Staff"}}`)})
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if string(raw) != `{"name":"Staff"}` {
		t.Errorf("data = %s", raw)
	}
}

// A profile banner, a module warning, or Windows CRLF endings must not be able
// to corrupt the parse. That is the whole reason for the sentinels.
func TestParseEnvelopeToleratesNoise(t *testing.T) {
	stdout := "WARNING: something\r\n" +
		"<<<TFAD:BEGIN>>>\r\n" +
		`{"ok":true,"data":{"name":"Staff"}}` + "\r\n" +
		"<<<TFAD:END>>>\r\n" +
		"trailing junk\r\n"
	raw, err := parseEnvelope("OU.Get", Result{Stdout: stdout})
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if string(raw) != `{"name":"Staff"}` {
		t.Errorf("data = %s", raw)
	}
}

func TestParseEnvelopeTransportFailures(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want string // substring the message must carry
	}{
		{"non-zero exit", Result{Stdout: "", Stderr: "pwsh: command not found", ExitCode: 127}, "pwsh: command not found"},
		{"missing begin", Result{Stdout: `{"ok":true,"data":{}}` + "\n<<<TFAD:END>>>"}, "envelope"},
		{"missing end", Result{Stdout: "<<<TFAD:BEGIN>>>\n" + `{"ok":true}`}, "envelope"},
		{"not json", Result{Stdout: env("this is not json")}, "decode"},
		{"no envelope at all", Result{Stdout: "Import-Module: module not found"}, "envelope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseEnvelope("OU.Get", tt.res)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrTransport) {
				t.Errorf("want KindTransport, got: %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("message %q missing %q", err.Error(), tt.want)
			}
		})
	}
}

// An exit code of 0 with ok:false is AD refusing the operation, which is a
// classified error and never a transport failure.
func TestParseEnvelopeADRefusal(t *testing.T) {
	body := `{"ok":false,"error":{` +
		`"type":"Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException",` +
		`"message":"Cannot find an object with identity: 'nope'",` +
		`"category":"ObjectNotFound","targetName":"nope",` +
		`"fqid":"ActiveDirectoryCmdlet:…,Microsoft.ActiveDirectory.Management.Commands.GetADUser",` +
		`"errorCode":8333,"serverErrorMessage":"0000208D: NameErr"}}`
	_, err := parseEnvelope("User.Get", Result{Stdout: env(body)})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Kind mismatch: %v", err)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatal("want an *Error")
	}
	if e.Op != "User.Get" {
		t.Errorf("Op = %q", e.Op)
	}
	if e.Code != 8333 || e.FQID == "" || e.Target != "nope" || e.ServerMessage == "" {
		t.Errorf("envelope fields lost: %+v", e)
	}
}

// errorCode and serverErrorMessage are probed by property, so they are absent
// on exceptions that do not implement IHasErrorCode. Classification must then
// fall back to the type.
func TestParseEnvelopeWithoutErrorCode(t *testing.T) {
	body := `{"ok":false,"error":{"type":"Microsoft.ActiveDirectory.Management.ADServerDownException",` +
		`"message":"Unable to contact the server","category":"ResourceUnavailable",` +
		`"targetName":"","fqid":"","errorCode":null,"serverErrorMessage":null}}`
	_, err := parseEnvelope("User.Get", Result{Stdout: env(body)})
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("want KindTransient, got %v", err)
	}
}
