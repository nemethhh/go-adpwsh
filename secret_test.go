package adpwsh

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const plaintext = "P@ssw0rd-do-not-leak"

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret(plaintext)
	for _, format := range []string{"%v", "%s", "%#v", "%+v"} {
		got := fmt.Sprintf(format, s)
		if strings.Contains(got, plaintext) {
			t.Errorf("format %s leaked the plaintext: %s", format, got)
		}
	}
	// A struct containing a Secret must be safe too — this is the shape a
	// credential actually travels in.
	type cred struct {
		User string
		Pass Secret
	}
	got := fmt.Sprintf("%v", cred{User: "svc_tf", Pass: s})
	if strings.Contains(got, plaintext) {
		t.Errorf("embedded Secret leaked the plaintext: %s", got)
	}
}

func TestSecretNeverMarshals(t *testing.T) {
	if _, err := json.Marshal(NewSecret(plaintext)); err == nil {
		t.Fatal("json.Marshal(Secret) succeeded; it must always fail")
	}
	type payload struct {
		Password Secret `json:"password"`
	}
	b, err := json.Marshal(payload{Password: NewSecret(plaintext)})
	if err == nil {
		t.Fatalf("json.Marshal of a struct holding a Secret succeeded: %s", b)
	}
}

func TestSecretReveal(t *testing.T) {
	if got := NewSecret(plaintext).reveal(); got != plaintext {
		t.Errorf("reveal() = %q, want the plaintext", got)
	}
	if !NewSecret("").IsZero() {
		t.Error("empty Secret must report IsZero")
	}
	if NewSecret("x").IsZero() {
		t.Error("non-empty Secret must not report IsZero")
	}
}
