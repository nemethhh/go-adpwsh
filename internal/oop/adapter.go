package oop

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrpcore/outofproc"
)

// Adapter runs the out-of-proc ack handshake over an outofproc.Transport and
// exposes an io.ReadWriter + MultiplexedTransport for go-psrpcore's runspace.
//
// CRITICAL (lab-proven): the readLoop sends CloseAck and SignalAck, but NEVER a
// DataAck. The -sshs/stdio server rejects a client DataAck and closes the pipe.
type Adapter struct {
	transport *outofproc.Transport

	readMu   sync.Mutex
	notifyCh chan struct{}
	pending  [][]byte
	closed   bool
	readErr  error

	ctx          context.Context
	cancel       context.CancelFunc
	readLoopDone chan struct{}

	readTimeout time.Duration
}

// New wires a raw stream (r read, w write) through the Framer and an
// outofproc.Transport into a ready-to-use Adapter.
func New(r io.Reader, w io.Writer, runspaceID uuid.UUID, readTimeout time.Duration) *Adapter {
	t := outofproc.NewTransportFromReadWriter(NewFramer(r, w))
	return NewAdapter(t, readTimeout)
}

// NewAdapter builds an Adapter over an already-constructed transport.
func NewAdapter(t *outofproc.Transport, readTimeout time.Duration) *Adapter {
	ctx, cancel := context.WithCancel(context.Background())
	a := &Adapter{
		transport:    t,
		notifyCh:     make(chan struct{}, 1),
		pending:      make([][]byte, 0, 16),
		ctx:          ctx,
		cancel:       cancel,
		readLoopDone: make(chan struct{}),
		readTimeout:  readTimeout,
	}
	go a.readLoop()
	return a
}

func (a *Adapter) readLoop() {
	defer func() {
		close(a.readLoopDone)
		a.readMu.Lock()
		a.closed = true
		a.readMu.Unlock()
		a.notify()
	}()
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		packet, err := a.transport.ReceivePacket()
		if err != nil {
			a.readMu.Lock()
			a.readErr = err
			a.readMu.Unlock()
			a.notify()
			return
		}
		switch packet.Type {
		case outofproc.PacketTypeData:
			// DO NOT SendDataAck here — the -sshs/stdio server rejects a client
			// DataAck ("unknown element DataAck") and closes. Just buffer it.
			a.readMu.Lock()
			a.pending = append(a.pending, packet.Data)
			a.readMu.Unlock()
			a.notify()
		case outofproc.PacketTypeClose:
			_ = a.transport.SendCloseAck(packet.PSGuid)
		case outofproc.PacketTypeSignal:
			_ = a.transport.SendSignalAck(packet.PSGuid)
		}
		// CommandAck/DataAck/SignalAck from the server need no action here.
	}
}

func (a *Adapter) notify() {
	select {
	case a.notifyCh <- struct{}{}:
	default:
	}
}

func (a *Adapter) Read(p []byte) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	var deadline time.Time
	if a.readTimeout > 0 {
		deadline = time.Now().Add(a.readTimeout)
	}
	for len(a.pending) == 0 && !a.closed && a.readErr == nil {
		a.readMu.Unlock()
		timer := time.NewTimer(1 * time.Second)
		select {
		case <-a.notifyCh:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-a.ctx.Done():
			timer.Stop()
			a.readMu.Lock()
			return 0, a.ctx.Err()
		}
		a.readMu.Lock()
		if !deadline.IsZero() && time.Now().After(deadline) {
			if len(a.pending) > 0 || a.closed || a.readErr != nil {
				break
			}
			return 0, fmt.Errorf("oop: read timeout after %s", a.readTimeout)
		}
	}
	if len(a.pending) > 0 {
		n := copy(p, a.pending[0])
		if n == len(a.pending[0]) {
			a.pending = a.pending[1:]
		} else {
			a.pending[0] = a.pending[0][n:]
		}
		return n, nil
	}
	if a.readErr != nil {
		return 0, a.readErr
	}
	if a.closed {
		return 0, io.EOF
	}
	return 0, nil
}

func (a *Adapter) Write(p []byte) (int, error) {
	if err := a.transport.SendData(outofproc.NullGUID, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// MultiplexedTransport methods go-psrpcore's runspace probes for.
func (a *Adapter) SendCommand(pipelineGUID uuid.UUID) error {
	return a.transport.SendCommand(pipelineGUID)
}

func (a *Adapter) SendPipelineData(pipelineGUID uuid.UUID, data []byte) error {
	time.Sleep(2 * time.Millisecond) // matches go-psrp's ordering guard
	return a.transport.SendData(pipelineGUID, data)
}

func (a *Adapter) SendSignal(pipelineGUID uuid.UUID) error {
	return a.transport.SendSignal(pipelineGUID)
}

func (a *Adapter) Close() error {
	a.cancel()
	select {
	case <-a.readLoopDone:
	case <-time.After(300 * time.Millisecond):
	}
	return nil
}
