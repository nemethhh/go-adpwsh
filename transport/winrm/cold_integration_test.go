//go:build psrplive

// Opt-in live test for the winrm+cold cell: one fresh WinRS shell per op over
// WSMan, feeding the wrapped op script on STDIN to `powershell.exe
// -EncodedCommand <bootstrap>` (no command-size limit). Exercises the two
// identities the cell separates: the WinRS TRANSPORT account (PSRP_USER, needs
// WinRS/Remote Management Users access) and the AD account delivered as
// -Credential inside the payload (AD_CRED_*, least-privilege). Run with:
//
//	KRB5_CONFIG=... KRB5CCNAME=... \
//	  PSRP_HOST=192.168.50.31 PSRP_SPN=HTTP/s-client.corp.local PSRP_REALM=CORP.LOCAL \
//	  PSRP_USER='CORP\svc_tfcold' \
//	  AD_CRED_USER='CORP\svc_tfacc' AD_CRED_PASS=... AD_SERVER=s-server.corp.local \
//	  go test -tags psrplive ./transport/winrm/ -run TestLiveCold -v
package winrm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveColdStdinGetADUser(t *testing.T) {
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
		Username:     os.Getenv("PSRP_USER"), // WinRS transport identity
		PwshPath:     os.Getenv("PSRP_PWSH"), // optional; cold defaults to powershell.exe (5.1)
		Timeout:      60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewCold: %v", err)
	}
	defer tr.Close()

	// The op script reads the JSON payload from [Console]::In (delivered by
	// WrapFullPayload's SetIn), rebuilds the AD credential, and queries AD. 5.1-
	// compatible (no ConvertFrom-Json -AsHashtable). ColdTransport delivers the
	// whole wrapped script over stdin, so an op far larger than the ~8191-char
	// cmd.exe command line still runs.
	script := `$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$c = @{}
if ($p.server) { $c['Server'] = $p.server }
if ($p.username) {
    $sec = ConvertTo-SecureString $p.password -AsPlainText -Force
    $c['Credential'] = New-Object System.Management.Automation.PSCredential($p.username, $sec)
}
$u = Get-ADUser -Identity krbtgt @c
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output (@{ ok=$true; data=@{ sam=$u.SamAccountName } } | ConvertTo-Json -Compress)
Write-Output '<<<TFAD:END>>>'`

	payload := fmt.Sprintf(`{"username":%q,"password":%q,"server":%q}`,
		os.Getenv("AD_CRED_USER"), os.Getenv("AD_CRED_PASS"), os.Getenv("AD_SERVER"))

	res, err := tr.Run(context.Background(), liveEncode(script), []byte(payload))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, `"ok":true`) || !strings.Contains(res.Stdout, "krbtgt") {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}
