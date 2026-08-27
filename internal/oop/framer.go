package oop

import (
	"bytes"
	"io"
)

// Framer re-frames a raw out-of-proc byte stream into clean, newline-delimited
// packets before go-psrpcore's outofproc.Transport parses them. Writes pass
// straight through. Ported from go-psrp's hvPacketReadWriter, minus the
// HVSocket-specific error sniffing.
type Framer struct {
	r          io.Reader
	w          io.Writer
	buf        []byte
	carry      []byte
	pendingErr error
}

// NewFramer wraps r (read side, re-framed) and w (write side, passthrough).
func NewFramer(r io.Reader, w io.Writer) *Framer { return &Framer{r: r, w: w} }

func (f *Framer) Read(p []byte) (int, error) {
	for len(f.buf) == 0 {
		if f.pendingErr != nil {
			err := f.pendingErr
			f.pendingErr = nil
			return 0, err
		}
		tmp := make([]byte, 32*1024)
		n, err := f.r.Read(tmp)
		if n == 0 {
			return 0, err
		}
		f.carry = append(f.carry, tmp[:n]...)
		out, remaining := splitOutOfProcPackets(f.carry)
		f.carry = remaining
		if len(out) > 0 {
			f.buf = out
			if err != nil {
				f.pendingErr = err
			}
			break
		}
		if err != nil {
			f.pendingErr = err
		}
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *Framer) Write(p []byte) (int, error) { return f.w.Write(p) }

func splitOutOfProcPackets(data []byte) (out, remaining []byte) {
	i := 0
	const maxSelfCloseLen = 256
	for i < len(data) {
		start := bytes.IndexByte(data[i:], '<')
		if start == -1 {
			return out, data[i:]
		}
		start += i
		if start > i {
			i = start
		}
		nextStart := bytes.IndexByte(data[start+1:], '<')
		if nextStart != -1 {
			nextStart = start + 1 + nextStart
		}
		if bytes.HasPrefix(data[start:], []byte("<Data ")) || bytes.HasPrefix(data[start:], []byte("<Data>")) {
			end := bytes.Index(data[start:], []byte("</Data>"))
			if end == -1 {
				break
			}
			endPos := start + end + len("</Data>")
			out = append(out, data[start:endPos]...)
			out = append(out, '\n')
			i = endPos
			continue
		}
		searchEnd := len(data)
		if lim := start + maxSelfCloseLen; lim < searchEnd {
			searchEnd = lim
		}
		end := bytes.Index(data[start:searchEnd], []byte("/>"))
		if end == -1 {
			break
		}
		endPos := start + end + 2
		if nextStart != -1 && nextStart < endPos {
			break
		}
		out = append(out, data[start:endPos]...)
		out = append(out, '\n')
		i = endPos
	}
	return out, data[i:]
}
