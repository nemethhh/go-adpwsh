package ssh_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

// Host key verification is on by default; disabling it takes an explicit
// opt-out. Setting two sources is a validation error rather than a silent
// precedence surprise.
func TestHostKeyPrecedenceValidation(t *testing.T) {
	hostKey := newTestServer(t, "u", "p").HostKeyLine
	base := adssh.Config{Host: "jump.corp.local", User: "svc_tf", Password: "x"}
	tests := []struct {
		name    string
		mut     func(*adssh.Config)
		wantErr string
	}{
		{"no source at all", func(c *adssh.Config) {}, "host key"},
		{"known_hosts alone is fine", func(c *adssh.Config) { c.KnownHostsFile = "/dev/null" }, ""},
		{"pinned key alone is fine", func(c *adssh.Config) { c.HostKey = hostKey }, ""},
		{"insecure alone is fine", func(c *adssh.Config) { c.InsecureIgnoreHostKey = true }, ""},
		{"both key and known_hosts", func(c *adssh.Config) {
			c.HostKey, c.KnownHostsFile = hostKey, "/dev/null"
		}, "host_key"},
		{"insecure wins over the others", func(c *adssh.Config) {
			c.InsecureIgnoreHostKey, c.KnownHostsFile = true, "/dev/null"
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mut(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tt.wantErr)
			}
		})
	}
}

// Exactly one credential source must resolve; supplying several is an error.
func TestAuthPrecedenceValidation(t *testing.T) {
	base := adssh.Config{Host: "jump.corp.local", User: "svc_tf", InsecureIgnoreHostKey: true}
	tests := []struct {
		name    string
		mut     func(*adssh.Config)
		wantErr string
	}{
		{"none", func(c *adssh.Config) {}, "exactly one"},
		{"password", func(c *adssh.Config) { c.Password = "x" }, ""},
		{"private key pem", func(c *adssh.Config) { c.PrivateKeyPEM = "-----BEGIN" }, ""},
		{"private key path", func(c *adssh.Config) { c.PrivateKeyPath = "/tmp/k" }, ""},
		{"agent", func(c *adssh.Config) { c.UseAgent = true }, ""},
		{"two of them", func(c *adssh.Config) { c.Password, c.UseAgent = "x", true }, "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mut(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := adssh.Config{Host: "jump", User: "svc_tf", Password: "x", InsecureIgnoreHostKey: true}
	got := cfg.WithDefaults()
	if got.Port != 22 || got.Concurrency != 4 || got.Timeout != 60*time.Second || got.PwshPath != "pwsh" ||
		got.RemoteTempDir != `C:\Windows\Temp` {
		t.Errorf("defaults = %+v", got)
	}
}

func dialConfig(s *testServer, user, password string) adssh.Config {
	host, port := splitHostPort(s.Addr)
	return adssh.Config{
		Host: host, Port: port, User: user, Password: password,
		HostKey: s.HostKeyLine, Concurrency: 2, Timeout: 5 * time.Second,
	}
}

func splitHostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return h, n
}

// The command must be the exact invocation the Transport contract documents,
// and the payload must arrive on stdin rather than on the command line.
func TestSSHRunsTheDocumentedCommandWithPayloadOnStdin(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	s.Reply = func(execRequest) (string, string, int) {
		return "<<<TFAD:BEGIN>>>\r\n{\"ok\":true,\"data\":{}}\r\n<<<TFAD:END>>>\r\n", "", 0
	}
	tr, err := adssh.New(dialConfig(s, "svc_tf", "hunter2"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	res, err := tr.Run(context.Background(), "QQBCAA==", []byte(`{"op":"rootdse"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "TFAD:BEGIN") {
		t.Errorf("result = %+v", res)
	}
	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests", len(reqs))
	}
	want := "pwsh -NoProfile -NonInteractive -EncodedCommand QQBCAA=="
	if reqs[0].Command != want {
		t.Errorf("command = %q, want %q", reqs[0].Command, want)
	}
	if string(reqs[0].Stdin) != `{"op":"rootdse"}` {
		t.Errorf("stdin = %q", reqs[0].Stdin)
	}
}

// A non-zero exit is data, not an error: the caller decides what it means.
func TestSSHReportsExitCodeAndStderrWithoutErroring(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	s.Reply = func(execRequest) (string, string, int) { return "", "pwsh: not found", 127 }
	tr, err := adssh.New(dialConfig(s, "svc_tf", "hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	res, err := tr.Run(context.Background(), "QQA=", nil)
	if err != nil {
		t.Fatalf("a non-zero exit must not be a transport error: %v", err)
	}
	if res.ExitCode != 127 || res.Stderr != "pwsh: not found" {
		t.Errorf("result = %+v", res)
	}
}

// The semaphore is the reason #119's failure mode cannot recur: sshd's default
// MaxSessions is 10 and Terraform's default parallelism is 10.
func TestSSHBoundsConcurrentChannels(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	release := make(chan struct{})
	s.Reply = func(execRequest) (string, string, int) {
		<-release
		return "<<<TFAD:BEGIN>>>\r\n{\"ok\":true,\"data\":{}}\r\n<<<TFAD:END>>>\r\n", "", 0
	}
	cfg := dialConfig(s, "svc_tf", "hunter2")
	cfg.Concurrency = 2
	tr, err := adssh.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = tr.Run(context.Background(), "QQA=", nil)
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := s.MaxConcurrentSessions(); got > 2 {
		t.Errorf("server saw %d concurrent sessions, want at most 2", got)
	}
}

func TestSSHRejectsAWrongHostKey(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	cfg := dialConfig(s, "svc_tf", "hunter2")
	other := newTestServer(t, "x", "y")
	cfg.HostKey = other.HostKeyLine
	if _, err := adssh.New(cfg); err == nil {
		t.Fatal("New must refuse a host presenting a different key")
	}
}

func TestSSHAuthFailureIsATransportError(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	_, err := adssh.New(dialConfig(s, "svc_tf", "wrong-password"))
	if err == nil {
		t.Fatal("New must fail on a rejected credential")
	}
	if !errors.Is(err, adpwsh.ErrTransport) {
		t.Errorf("want KindTransport, got %v", err)
	}
}

func TestSSHCancellationStopsARun(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	s.Reply = func(execRequest) (string, string, int) { <-block; return "", "", 0 }

	tr, err := adssh.New(dialConfig(s, "svc_tf", "hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := tr.Run(ctx, "QQA=", nil); err == nil {
		t.Fatal("Run must return when the context expires")
	}
}

// A command short enough for -EncodedCommand must never take the SFTP
// fallback: no -File on the command line.
func TestRunSmallCommandUsesEncodedCommand(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")
	s.Reply = func(execRequest) (string, string, int) {
		return "<<<TFAD:BEGIN>>>\r\n{\"ok\":true,\"data\":{}}\r\n<<<TFAD:END>>>\r\n", "", 0
	}
	tr, err := adssh.New(dialConfig(s, "svc_tf", "hunter2"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	if _, err := tr.Run(context.Background(), "QQBCAA==", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests", len(reqs))
	}
	want := "pwsh -NoProfile -NonInteractive -EncodedCommand QQBCAA=="
	if reqs[0].Command != want {
		t.Errorf("command = %q, want %q", reqs[0].Command, want)
	}
	if strings.Contains(reqs[0].Command, "-File") {
		t.Errorf("command = %q, must not use the SFTP fallback", reqs[0].Command)
	}
}

// A command at or beyond the large-command threshold must be written to a
// temp file over SFTP and run with -File, with the payload still arriving on
// the exec session's stdin, and the temp file removed once Run returns.
func TestRunLargeCommandUsesSFTP(t *testing.T) {
	s := newTestServer(t, "svc_tf", "hunter2")

	var gotCommand string
	var gotFileContent []byte
	var gotFilePath string
	s.Reply = func(req execRequest) (string, string, int) {
		gotCommand = req.Command
		gotFilePath = commandFilePath(req.Command)
		if gotFilePath == "" {
			return "", "no -File path found in " + req.Command, 1
		}
		data, err := os.ReadFile(gotFilePath)
		if err != nil {
			return "", err.Error(), 1
		}
		gotFileContent = data
		return "<<<TFAD:BEGIN>>>\r\n{\"ok\":true,\"data\":{}}\r\n<<<TFAD:END>>>\r\n", "", 0
	}

	remoteDir := t.TempDir()
	cfg := dialConfig(s, "svc_tf", "hunter2")
	cfg.RemoteTempDir = remoteDir
	tr, err := adssh.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	script := strings.Repeat("Write-Output 'padding to clear the large-command threshold'; ", 200)
	encoded := adscript.EncodeCommand(script)
	if len(encoded) < 7000 {
		t.Fatalf("test script too short to trigger the SFTP fallback: encoded length %d", len(encoded))
	}

	res, err := tr.Run(context.Background(), encoded, []byte(`{"op":"rootdse"}`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "TFAD:BEGIN") {
		t.Fatalf("result = %+v", res)
	}

	if strings.Contains(gotCommand, "-EncodedCommand") || !strings.Contains(gotCommand, "-File ") {
		t.Errorf("command = %q, want -File and not -EncodedCommand", gotCommand)
	}
	if !strings.HasPrefix(gotFilePath, remoteDir) {
		t.Errorf("temp file %q not under RemoteTempDir %q", gotFilePath, remoteDir)
	}
	if string(gotFileContent) != script {
		t.Errorf("remote file content differed from the decoded script (len %d vs %d)", len(gotFileContent), len(script))
	}

	reqs := s.Requests()
	if len(reqs) != 1 || string(reqs[0].Stdin) != `{"op":"rootdse"}` {
		t.Errorf("payload did not arrive on the exec session's stdin: %+v", reqs)
	}

	if _, err := os.Stat(gotFilePath); !os.IsNotExist(err) {
		t.Errorf("temp file %q still exists after Run, stat err = %v", gotFilePath, err)
	}
}

// commandFilePath extracts the quoted path following "-File " from a command
// line built by the SFTP fallback.
func commandFilePath(cmd string) string {
	const marker = `-File "`
	i := strings.Index(cmd, marker)
	if i < 0 {
		return ""
	}
	rest := cmd[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
