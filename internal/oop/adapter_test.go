package oop

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// scriptedServer speaks raw out-of-proc text on its end of a net.Pipe. It records
// every packet it receives from the adapter so tests can assert what the client
// sent (crucially: whether it sent a forbidden DataAck).
func TestAdapter_NeverSendsClientDataAck(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	id := uuid.New()
	a := New(client, client, id, 5*time.Second)
	defer a.Close()

	received := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(server)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			received <- sc.Text()
		}
	}()

	// Server sends a Data packet to the client (as pwsh would). Base64 "AAAA".
	if _, err := server.Write([]byte("<Data Stream='Default' PSGuid='00000000-0000-0000-0000-000000000000'>AAAA</Data>\n")); err != nil {
		t.Fatalf("server write Data: %v", err)
	}

	// The client (adapter) must NOT reply with a DataAck. Give it a moment,
	// then send a Close and confirm the ONLY thing we ever receive is a CloseAck.
	time.Sleep(200 * time.Millisecond)
	if _, err := server.Write([]byte("<Close PSGuid='00000000-0000-0000-0000-000000000000' />\n")); err != nil {
		t.Fatalf("server write Close: %v", err)
	}

	deadline := time.After(2 * time.Second)
	sawCloseAck := false
	for !sawCloseAck {
		select {
		case line := <-received:
			if strings.Contains(line, "DataAck") {
				t.Fatalf("adapter sent a forbidden DataAck: %q", line)
			}
			if strings.Contains(line, "CloseAck") {
				sawCloseAck = true
			}
		case <-deadline:
			t.Fatal("never saw CloseAck")
		}
	}
}
