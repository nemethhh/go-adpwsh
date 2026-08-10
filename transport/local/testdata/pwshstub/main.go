// Command pwshstub stands in for pwsh in the local transport's tests. What is
// under test is process handling — the argument list, the payload on stdin,
// exit codes, the timeout, cancellation and the concurrency bound — not
// PowerShell's own behaviour, so none of it needs PowerShell.
//
// Everything it does is driven by environment variables, because the transport
// controls the argument list completely and deliberately: a test cannot ask for
// behaviour by passing a flag.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// record is one JSON line appended to the file named by PWSHSTUB_RECORD. Each
// invocation writes one on entry and, if it runs to completion, a second with
// Finished set — which is how a test proves a kill actually happened rather
// than the child merely being abandoned.
type record struct {
	Args     []string `json:"args"`
	Stdin    string   `json:"stdin"`
	Dir      string   `json:"dir"`
	Finished bool     `json:"finished"`
}

func main() {
	// Read stdin to completion, as the real preamble's
	// [Console]::In.ReadToEnd() does.
	stdin, _ := io.ReadAll(os.Stdin)
	dir, _ := os.Getwd()
	rec := record{Args: os.Args[1:], Stdin: string(stdin), Dir: dir}
	appendRecord(rec)

	// PWSHSTUB_GATE holds every invocation open at once, which is how the
	// concurrency bound is observed rather than inferred from timing.
	if addr := os.Getenv("PWSHSTUB_GATE"); addr != "" {
		gate(addr)
	}
	if ms := os.Getenv("PWSHSTUB_SLEEP_MS"); ms != "" {
		n, err := strconv.Atoi(ms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pwshstub: bad PWSHSTUB_SLEEP_MS %q\n", ms)
			os.Exit(2)
		}
		time.Sleep(time.Duration(n) * time.Millisecond)
	}

	rec.Finished = true
	appendRecord(rec)

	fmt.Fprint(os.Stdout, os.Getenv("PWSHSTUB_STDOUT"))
	fmt.Fprint(os.Stderr, os.Getenv("PWSHSTUB_STDERR"))
	if code := os.Getenv("PWSHSTUB_EXIT"); code != "" {
		n, err := strconv.Atoi(code)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pwshstub: bad PWSHSTUB_EXIT %q\n", code)
			os.Exit(2)
		}
		os.Exit(n)
	}
}

func appendRecord(rec record) {
	path := os.Getenv("PWSHSTUB_RECORD")
	if path == "" {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	// One write of one short line: O_APPEND is what keeps concurrent
	// invocations from interleaving their records.
	_, _ = f.Write(append(line, '\n'))
}

// gate announces this invocation on the test's listener and blocks until the
// test writes a byte back.
func gate(addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwshstub: cannot reach the gate at %s: %v\n", addr, err)
		os.Exit(3)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("started\n"))
	buf := make([]byte, 1)
	_, _ = io.ReadFull(conn, buf)
}
