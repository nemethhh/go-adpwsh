package oop

import (
	"net"
	"testing"
	"time"
)

func TestSplitOutOfProcPackets(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		wantOut       string
		wantRemaining string
	}{
		{
			name:          "one self-closing packet",
			in:            "<DataAck PSGuid='00000000-0000-0000-0000-000000000000' />",
			wantOut:       "<DataAck PSGuid='00000000-0000-0000-0000-000000000000' />\n",
			wantRemaining: "",
		},
		{
			name:          "one data packet",
			in:            "<Data Stream='Default' PSGuid='x'>AAAA</Data>",
			wantOut:       "<Data Stream='Default' PSGuid='x'>AAAA</Data>\n",
			wantRemaining: "",
		},
		{
			name:          "two concatenated packets",
			in:            "<Data Stream='Default' PSGuid='x'>AAAA</Data><DataAck PSGuid='x' />",
			wantOut:       "<Data Stream='Default' PSGuid='x'>AAAA</Data>\n<DataAck PSGuid='x' />\n",
			wantRemaining: "",
		},
		{
			name:          "partial data packet is carried",
			in:            "<Data Stream='Default' PSGuid='x'>AAAA</Da",
			wantOut:       "",
			wantRemaining: "<Data Stream='Default' PSGuid='x'>AAAA</Da",
		},
		{
			name:          "partial self-closing packet is carried",
			in:            "<Data Stream='Default' PSGuid='x'>AAAA</Data><DataAck PSGuid='x'",
			wantOut:       "<Data Stream='Default' PSGuid='x'>AAAA</Data>\n",
			wantRemaining: "<DataAck PSGuid='x'",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rem := splitOutOfProcPackets([]byte(c.in))
			if string(out) != c.wantOut {
				t.Errorf("out = %q, want %q", out, c.wantOut)
			}
			if string(rem) != c.wantRemaining {
				t.Errorf("remaining = %q, want %q", rem, c.wantRemaining)
			}
		})
	}
}

func TestFramer_ReassemblesAcrossChunks(t *testing.T) {
	// A single logical packet delivered in two raw reads must surface once, whole.
	pr, pw := net.Pipe()
	defer pr.Close()
	defer pw.Close()
	f := NewFramer(pr, pw)

	go func() {
		_, _ = pw.Write([]byte("<Data Stream='Default' PSGuid='x'>AAA"))
		time.Sleep(50 * time.Millisecond)
		_, _ = pw.Write([]byte("A</Data>"))
	}()

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	got := string(buf[:n])
	if got != "<Data Stream='Default' PSGuid='x'>AAAA</Data>\n" {
		t.Fatalf("reassembled = %q", got)
	}
}
