package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type execRequest struct {
	Command string
	Stdin   []byte
}

type testServer struct {
	Addr        string
	HostKeyLine string

	mu       sync.Mutex
	requests []execRequest
	maxOpen  int
	open     int

	// Reply is called for each exec; it returns stdout, stderr and the exit
	// status the client should see.
	Reply func(req execRequest) (string, string, int)

	listener net.Listener
	signer   ssh.Signer
}

func newTestServer(t *testing.T, user, password string) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{
		Addr:        ln.Addr().String(),
		HostKeyLine: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		listener:    ln,
		signer:      signer,
		Reply:       func(execRequest) (string, string, int) { return "", "", 0 },
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pw) == password {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	cfg.AddHostKey(signer)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *testServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, chReqs)
	}
}

func (s *testServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	s.mu.Lock()
	s.open++
	if s.open > s.maxOpen {
		s.maxOpen = s.open
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()

	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)

			stdin, _ := io.ReadAll(ch)
			call := execRequest{Command: payload.Command, Stdin: stdin}
			s.mu.Lock()
			s.requests = append(s.requests, call)
			s.mu.Unlock()

			stdout, stderr, status := s.Reply(call)
			_, _ = io.WriteString(ch, stdout)
			_, _ = io.WriteString(ch.Stderr(), stderr)
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(status))
			_, _ = ch.SendRequest("exit-status", false, b)
			return

		case "subsystem":
			// The large-command fallback opens this over the same
			// ssh.Client via sftp.NewClient, which requests the "sftp"
			// subsystem on a session channel exactly like a real Windows
			// OpenSSH server does. Serving the real filesystem here is what
			// lets the fallback write, and later remove, an actual temp file
			// under test.
			var payload struct{ Name string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			if payload.Name != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			if srv, err := sftp.NewServer(ch); err == nil {
				_ = srv.Serve()
			}
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *testServer) Requests() []execRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]execRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

func (s *testServer) MaxConcurrentSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxOpen
}
