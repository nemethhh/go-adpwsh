package oop

import (
	"testing"
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
