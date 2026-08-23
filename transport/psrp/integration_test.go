//go:build psrplive

// Opt-in live test. Requires a reachable WinRM host with the PowerShell.7
// endpoint and an ambient Kerberos ticket (kinit). Run with:
//
//	KRB5_CONFIG=... KRB5CCNAME=... PSRP_HOST=192.168.50.216 \
//	  PSRP_SPN=HTTP/s-server.corp.local \
//	  go test -tags psrplive ./transport/psrp/ -run TestLive -v
package psrp

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func liveEncode(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLiveGetADDomain(t *testing.T) {
	host := os.Getenv("PSRP_HOST")
	if host == "" {
		t.Skip("set PSRP_HOST to run the live PSRP test")
	}
	tr, err := New(Config{
		Host:         host,
		SPN:          os.Getenv("PSRP_SPN"),
		Realm:        os.Getenv("PSRP_REALM"),
		Krb5ConfPath: os.Getenv("KRB5_CONFIG"),
		CCachePath:   strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:"),
		Username:     os.Getenv("PSRP_USER"),
		Timeout:      60 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	script := `$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable
$c=@{}; if($p.server){$c['Server']=$p.server}
$d = Get-ADDomain @c
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output (@{ ok=$true; data=@{ dns=$d.DNSRoot } } | ConvertTo-Json -Compress)
Write-Output '<<<TFAD:END>>>'`

	res, err := tr.Run(context.Background(), liveEncode(script), []byte(`{"server":null}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, `"ok":true`) {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}
