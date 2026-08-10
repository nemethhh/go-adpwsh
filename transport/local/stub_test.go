package local_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// stubPath is the compiled pwsh stand-in, built once for the whole package.
var stubPath string

// TestMain builds the stub before any test runs. Compiling it rather than
// shipping a shell script keeps these tests running on every platform the
// transport itself supports, including the Windows host the transport exists
// for. testdata is excluded from ./... wildcards, so the stub never enters
// go build, go vet or the module's dependency-boundary test — but an explicit
// path still builds it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pwshstub")
	if err != nil {
		panic("cannot create the stub's directory: " + err.Error())
	}
	stubPath = filepath.Join(dir, "pwshstub")
	if runtime.GOOS == "windows" {
		stubPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", stubPath, "./testdata/pwshstub")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("cannot build the pwsh stub: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// stubRecord mirrors the stub's own record type.
type stubRecord struct {
	Args     []string `json:"args"`
	Stdin    string   `json:"stdin"`
	Dir      string   `json:"dir"`
	Finished bool     `json:"finished"`
}

// recordFile returns a fresh record path and points the stub at it.
func recordFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	t.Setenv("PWSHSTUB_RECORD", path)
	return path
}

// stubRecords reads back what the stub recorded, in order. A missing file means
// nothing ran, which is a legitimate assertion rather than an error.
func stubRecords(t *testing.T, path string) []stubRecord {
	t.Helper()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("cannot read the stub's records: %v", err)
	}
	defer func() { _ = f.Close() }()

	var out []stubRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec stubRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("cannot decode a stub record %q: %v", line, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("cannot scan the stub's records: %v", err)
	}
	return out
}

// gateServer counts how many stub invocations are inside the gate at once and
// releases them all when the test says so. Counting connections is what makes
// the concurrency assertion an observation rather than an inference from
// timing.
type gateServer struct {
	Addr string

	mu      sync.Mutex
	open    int
	maxOpen int

	release chan struct{}
	ln      net.Listener
}

func newGateServer(t *testing.T) *gateServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &gateServer{Addr: ln.Addr().String(), release: make(chan struct{}), ln: ln}
	go g.serve()
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("PWSHSTUB_GATE", g.Addr)
	return g
}

func (g *gateServer) serve() {
	for {
		conn, err := g.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			g.mu.Lock()
			g.open++
			if g.open > g.maxOpen {
				g.maxOpen = g.open
			}
			g.mu.Unlock()

			<-g.release
			_, _ = conn.Write([]byte("g"))

			g.mu.Lock()
			g.open--
			g.mu.Unlock()
		}()
	}
}

// Release lets every waiting invocation finish. Calling it twice panics, which
// is the right outcome for a test that lost track of its own gate.
func (g *gateServer) Release() { close(g.release) }

// MaxOpen is the high-water mark of simultaneous invocations.
func (g *gateServer) MaxOpen() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maxOpen
}

// The stub is test scaffolding, so it gets a test of its own: a broken stub
// would otherwise present as a broken transport.
func TestStubRecordsWhatItWasGiven(t *testing.T) {
	records := recordFile(t)
	t.Setenv("PWSHSTUB_STDOUT", "out")
	t.Setenv("PWSHSTUB_STDERR", "err")
	t.Setenv("PWSHSTUB_EXIT", "3")

	cmd := exec.Command(stubPath, "-NoProfile", "-EncodedCommand", "QQA=")
	cmd.Stdin = strings.NewReader("payload")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("stub exit = %v, want exit status 3", err)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}

	recs := stubRecords(t, records)
	if len(recs) != 2 {
		t.Fatalf("recorded %d entries, want 2 (one on entry, one on completion)", len(recs))
	}
	if recs[0].Stdin != "payload" {
		t.Errorf("stdin = %q, want payload", recs[0].Stdin)
	}
	if want := []string{"-NoProfile", "-EncodedCommand", "QQA="}; !slices.Equal(recs[0].Args, want) {
		t.Errorf("args = %q, want %q", recs[0].Args, want)
	}
	if recs[0].Finished || !recs[1].Finished {
		t.Errorf("finished flags = %v then %v, want false then true", recs[0].Finished, recs[1].Finished)
	}
}
