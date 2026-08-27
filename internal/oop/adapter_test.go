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

func TestAdapter_RoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	a := New(client, client, uuid.New(), 5*time.Second)
	defer a.Close()

	// Server -> client Data becomes readable via Adapter.Read (decoded bytes).
	go func() {
		// "AAAA" base64-decodes to 0x00 0x00 0x00.
		_, _ = server.Write([]byte("<Data Stream='Default' PSGuid='00000000-0000-0000-0000-000000000000'>AAAA</Data>\n"))
	}()
	buf := make([]byte, 16)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 3 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
		t.Fatalf("decoded server Data = %v (n=%d), want [0 0 0]", buf[:n], n)
	}

	// Client -> server: Adapter.Write emits a <Data> element the server can read.
	got := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(server)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		if sc.Scan() {
			got <- sc.Text()
		}
	}()
	if _, err := a.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "<Data ") || !strings.Contains(line, "</Data>") {
			t.Fatalf("client did not emit a Data element: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the client's Data")
	}
}
