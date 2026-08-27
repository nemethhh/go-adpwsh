//go:build psrplive

// Opt-in live test for the winrm+cold cell: one fresh WinRS `pwsh
// -EncodedCommand` per op over WSMan. Shares env/setup with
// integration_test.go (and its liveEncode helper); build the transport with
// NewCold instead of New. Requires a reachable WinRM host with pwsh 7 on PATH
// and an ambient Kerberos ticket (kinit). Run with:
//
//	KRB5_CONFIG=... KRB5CCNAME=... PSRP_HOST=192.168.50.216 \
//	  PSRP_SPN=HTTP/s-server.corp.local \
//	  go test -tags psrplive ./transport/winrm/ -run TestLiveCold -v
package winrm

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveColdGetADUser(t *testing.T) {
	host := os.Getenv("PSRP_HOST")
	if host == "" {
		t.Skip("set PSRP_HOST to run the live winrm-cold test")
	}
	tr, err := NewCold(Config{
		Host:         host,
		SPN:          os.Getenv("PSRP_SPN"),
		Realm:        os.Getenv("PSRP_REALM"),
		Krb5ConfPath: os.Getenv("KRB5_CONFIG"),
		CCachePath:   strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:"),
		Username:     os.Getenv("PSRP_USER"),
		PwshPath:     os.Getenv("PSRP_PWSH"), // optional; defaults to "pwsh"
		Timeout:      60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewCold: %v", err)
	}
	defer tr.Close()

	// The raw op script reads the JSON payload from [Console]::In; ColdTransport
	// wraps it with WrapFullPayload ([Console]::SetIn) and re-encodes before
	// handing it to WinRS, so the SetIn payload path is exercised end-to-end.
	script := `$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable
$c=@{}; if($p.server){$c['Server']=$p.server}
$u = Get-ADUser -Identity krbtgt @c
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output (@{ ok=$true; data=@{ sam=$u.SamAccountName } } | ConvertTo-Json -Compress)
Write-Output '<<<TFAD:END>>>'`

	res, err := tr.Run(context.Background(), liveEncode(script), []byte(`{"server":null}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, `"ok":true`) {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "krbtgt") {
		t.Errorf("expected krbtgt in output, got %q", res.Stdout)
	}
}
