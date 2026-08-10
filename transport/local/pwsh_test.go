package local_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	adlocal "github.com/nemethhh/go-adpwsh/transport/local"
)

// requireRealPwsh resolves PowerShell or skips. This tier must never become a
// prerequisite for `go test ./...` on a machine without PowerShell: the stub tier
// is what guarantees the transport's behaviour everywhere, and this one adds the
// two properties only real pwsh can attest to.
func requireRealPwsh(t *testing.T) string {
	t.Helper()
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not on PATH; the stub tier covers the transport's own behaviour")
	}
	return pwsh
}

// echoScript reads the payload the way every shipped script's preamble does and
// writes back what it saw, framed by the library's sentinels. It deliberately
// does not Import-Module ActiveDirectory: that module is Windows-only, and none
// of the properties under test here need it.
//
// It is a constant, and every value it handles arrives as JSON on stdin — the
// same rule the library imposes on itself.
const echoScript = `
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable
$out = [ordered]@{
    commandLine = [Environment]::GetCommandLineArgs()
    values      = $p.values
}
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output ($out | ConvertTo-Json -Depth 6 -Compress)
Write-Output '<<<TFAD:END>>>'
`

type echoResult struct {
	CommandLine []string          `json:"commandLine"`
	Values      map[string]string `json:"values"`
}

// runEcho runs echoScript with values on stdin and decodes what came back.
func runEcho(t *testing.T, tr *adlocal.Transport, values map[string]string) echoResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"values": values})
	if err != nil {
		t.Fatal(err)
	}
	res, err := tr.Run(context.Background(), adscript.EncodeCommand(echoScript), body)
	if err != nil {
		t.Fatalf("Run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Fatalf("pwsh exited %d: %s", res.ExitCode, res.Stderr)
	}

	const begin, end = "<<<TFAD:BEGIN>>>", "<<<TFAD:END>>>"
	i, j := strings.Index(res.Stdout, begin), strings.Index(res.Stdout, end)
	if i < 0 || j < i {
		t.Fatalf("no envelope in the output: %q", res.Stdout)
	}
	var out echoResult
	body = []byte(strings.TrimSpace(res.Stdout[i+len(begin) : j]))
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("cannot decode %s: %v", body, err)
	}
	return out
}

// Real pwsh must accept the encoder's output and run exactly the script that
// went in. Until now the encoder was only ever round-tripped through its own
// decoder, which cannot catch a wrong byte order or a missing BOM assumption.
func TestRealPwshAcceptsTheEncodedCommand(t *testing.T) {
	requireRealPwsh(t)
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: 30 * time.Second})

	got := runEcho(t, tr, map[string]string{"probe": "hello"})
	if got.Values["probe"] != "hello" {
		t.Errorf("values = %v, want probe=hello", got.Values)
	}
	// The transport's documented invocation, as the process itself reports it.
	// Element 0 is the host assembly, so the flags start at 1.
	if len(got.CommandLine) < 5 {
		t.Fatalf("command line = %q, want at least 5 elements", got.CommandLine)
	}
	if want := []string{"-NoProfile", "-NonInteractive", "-EncodedCommand"}; !slices.Equal(got.CommandLine[1:4], want) {
		t.Errorf("command line = %q, want %q at 1..3", got.CommandLine, want)
	}
	if got.CommandLine[4] != adscript.EncodeCommand(echoScript) {
		t.Error("the encoded command pwsh received is not the one the encoder produced")
	}
}

// The property that keeps a password out of the host's process table: only the
// base64 script reaches argv, and no payload value ever does. Nothing but the
// process itself can report this, which is why it needs real pwsh.
func TestRealPwshNeverSeesPayloadValuesOnArgv(t *testing.T) {
	requireRealPwsh(t)
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: 30 * time.Second})

	const secret = "Correct-Horse-Battery-Staple-1"
	got := runEcho(t, tr, map[string]string{"password": secret})
	if got.Values["password"] != secret {
		t.Fatalf("the payload did not arrive: %v", got.Values)
	}
	for i, arg := range got.CommandLine {
		if strings.Contains(arg, secret) {
			t.Errorf("command line element %d contains the payload value; a password would be "+
				"visible in the host's process table", i)
		}
	}
}

// The eleven values that each broke the archived provider at least once, through
// a real PowerShell parser rather than the fake. This is what "no value ever
// becomes script text" means in practice: they travel as JSON on stdin and come
// back byte-for-byte, with no escaping layer anywhere to get wrong.
func TestRealPwshRoundTripsHostileValues(t *testing.T) {
	requireRealPwsh(t)
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: 30 * time.Second})

	values := map[string]string{
		"underscore":    "under_score",
		"double_quote":  `has "quotes"`,
		"single_quote":  `O'Brien`,
		"dollar":        `$env:PATH`,
		"backtick":      "back`tick",
		"semicolon":     "semi;colon",
		"ampersand":     "amper&sand",
		"pipe":          "pipe|char",
		"comma":         "Smith, John",
		"non_ascii":     "söüäß-éòñ",
		"subexpression": `$(Get-Process)`,
		// Not from the archived provider's history, but the two that would give
		// away a naive quoting layer hiding anywhere in the path.
		"newline":   "line one\nline two",
		"backslash": `C:\Windows\System32`,
	}

	got := runEcho(t, tr, values)
	for name, want := range values {
		if g := got.Values[name]; g != want {
			t.Errorf("%s round-tripped as %q, want %q", name, g, want)
		}
	}
}

// A real non-zero exit and real stderr, to confirm the exec plumbing agrees with
// what the stub asserts.
func TestRealPwshNonZeroExitIsData(t *testing.T) {
	requireRealPwsh(t)
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: 30 * time.Second})

	const script = `
[Console]::Error.Write('real stderr text')
exit 3
`
	res, err := tr.Run(context.Background(), adscript.EncodeCommand(script), nil)
	if err != nil {
		t.Fatalf("a non-zero exit must not be a transport error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
	if res.Stderr != "real stderr text" {
		t.Errorf("Stderr = %q", res.Stderr)
	}
}

// A real PowerShell process, really killed. The marker file is the proof: an
// abandoned pwsh finishes its sleep and writes it.
func TestRealPwshTimeoutKillsARealProcess(t *testing.T) {
	requireRealPwsh(t)
	marker := filepath.Join(t.TempDir(), "finished.txt")

	// The path arrives on stdin rather than in the script text, because that rule
	// holds in tests too.
	const script = `
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable
Start-Sleep -Seconds 30
Set-Content -Path $p.marker -Value 'finished'
`
	body, err := json.Marshal(map[string]any{"marker": marker})
	if err != nil {
		t.Fatal(err)
	}

	// pwsh starts in roughly 0.2s on this machine, so one second is enough to be
	// certain the script began and far short of its thirty-second sleep.
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: time.Second})
	start := time.Now()
	_, err = tr.Run(context.Background(), adscript.EncodeCommand(script), body)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Run must fail when the operation exceeds the timeout")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Run took %s; it must not wait for the child", elapsed)
	}

	// Well short of the sleep, and long enough that a surviving process would
	// have to be genuinely stuck rather than merely slow.
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Error("the marker exists; the process ran to completion and was not killed")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cannot check the marker: %v", err)
	}
}

// The ActiveDirectory module is Windows-only, so a script that needs it fails
// here — which happens to reproduce the single most likely first-run failure on a
// real host: RSAT-AD-PowerShell not installed. The shipped preamble calls
// Import-Module *outside* its try/catch, deliberately, so this failure produces
// no envelope and must be classified as a transport problem rather than as an
// Active Directory refusal.
//
// Note what stderr actually contains. PowerShell serializes error records as
// CLIXML when stderr is redirected, so this is a wrapped blob with ANSI escapes
// rather than prose — the human-readable sentence is inside it. Direct
// [Console]::Error.Write output is unaffected, which is why the exit-code test
// above sees plain text. See the finding recorded at the end of this plan.
func TestRealPwshMissingActiveDirectoryModuleIsATransportFailure(t *testing.T) {
	requireRealPwsh(t)
	tr := newTransport(t, adlocal.Config{PwshPath: "pwsh", Timeout: 30 * time.Second})

	const script = `
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
Write-Output 'unreachable'
`
	res, err := tr.Run(context.Background(), adscript.EncodeCommand(script), nil)
	// Run itself succeeds: the process ran, and a non-zero exit is data.
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode == 0 {
		t.Skip("this machine has the ActiveDirectory module after all; nothing to assert")
	}
	if !strings.Contains(res.Stderr, "ActiveDirectory") {
		t.Errorf("stderr should name the module pwsh could not load: %q", res.Stderr)
	}
	// No envelope: the script died before the epilogue could write one. This is
	// exactly the input parseEnvelope must classify as KindTransport.
	if strings.Contains(res.Stdout, "<<<TFAD:BEGIN>>>") {
		t.Error("a script that died before the epilogue must not have produced an envelope")
	}
	if strings.TrimSpace(res.Stdout) != "" {
		t.Errorf("stdout should be empty, got %q", res.Stdout)
	}
}

// The guard must skip, not fail, on a machine without PowerShell — otherwise this
// tier silently becomes a prerequisite for the whole suite. Emptying PATH for the
// process is enough to make the lookup fail, and t.Run reports a skipped subtest
// as a pass, so the t.Error below not running is the assertion.
func TestRequireRealPwshSkipsWithoutPowerShell(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	guardSkipped := t.Run("guard", func(t *testing.T) {
		requireRealPwsh(t)
		t.Error("requireRealPwsh returned instead of skipping when pwsh is not on PATH")
	})
	if !guardSkipped {
		t.Error("the guard did not skip: this tier would fail on a machine without PowerShell")
	}
}
