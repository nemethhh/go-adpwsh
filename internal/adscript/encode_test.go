package adscript

import (
	"encoding/base64"
	"strings"
	"testing"
)

// -EncodedCommand takes UTF-16LE base64. Its alphabet passes through cmd.exe
// unmangled, which is what makes the jump box's DefaultShell setting unable to
// corrupt the command.
func TestEncodeCommand(t *testing.T) {
	got := EncodeCommand("Get-ADUser")
	// "Get-ADUser" in UTF-16LE.
	want := base64.StdEncoding.EncodeToString([]byte{
		'G', 0, 'e', 0, 't', 0, '-', 0, 'A', 0, 'D', 0, 'U', 0, 's', 0, 'e', 0, 'r', 0,
	})
	if got != want {
		t.Errorf("EncodeCommand = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, " \t\n'\"") {
		t.Errorf("encoded command %q contains characters a shell could mangle", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, in := range []string{"", "Get-ADUser", "söüäß-éòñ \"quoted\" $var `tick`", "多字节"} {
		out, err := DecodeCommand(EncodeCommand(in))
		if err != nil {
			t.Fatalf("DecodeCommand: %v", err)
		}
		if out != in {
			t.Errorf("round trip changed %q into %q", in, out)
		}
	}
}
