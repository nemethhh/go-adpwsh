package fake_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func TestFakeSynthesizesASuccessEnvelope(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op != "ou_read" {
			t.Errorf("Op = %q", c.Op)
		}
		if c.Payload["identity"] != "9f2c" {
			t.Errorf("payload identity = %v", c.Payload["identity"])
		}
		// The fake decodes what would actually run, so a test can assert on
		// the script rather than trusting that one was built.
		if !strings.Contains(c.Script, "Get-ADOrganizationalUnit") {
			t.Errorf("script does not run the expected cmdlet:\n%s", c.Script)
		}
		return fake.OK(map[string]any{"name": "Staff"})
	})

	res, err := tr.Run(context.Background(), encodeFor(t, "ou_read"), []byte(`{"op":"ou_read","identity":"9f2c"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.Stdout, "<<<TFAD:BEGIN>>>") || !strings.Contains(res.Stdout, `"ok":true`) {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if len(tr.Calls()) != 1 {
		t.Errorf("Calls() = %d, want 1", len(tr.Calls()))
	}
}

func TestFakeInjectsErrors(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Fail("Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException", "nope", 0x208D)
	})
	res, err := tr.Run(context.Background(), encodeFor(t, "ou_read"), []byte(`{"op":"ou_read"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.Stdout, `"ok":false`) || !strings.Contains(res.Stdout, "8333") {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestFakeRawAndRunError(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response {
		return fake.Raw("garbage", "boom", 127)
	})
	res, err := tr.Run(context.Background(), encodeFor(t, "ou_read"), []byte(`{"op":"ou_read"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 127 || res.Stderr != "boom" || res.Stdout != "garbage" {
		t.Errorf("raw response not passed through: %+v", res)
	}
}

func encodeFor(t *testing.T, op string) string {
	t.Helper()
	s, err := adscript.Script(op)
	if err != nil {
		t.Fatal(err)
	}
	return adscript.EncodeCommand(s)
}
