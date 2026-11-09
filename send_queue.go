package quic

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/apernet/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendMTUProbe(*packetBuffer, protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf      *packetBuffer
	gsoSize  uint16
	ecn      protocol.ECN
	mtuProbe bool
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
	sendMu      sync.Mutex // orders packet ownership against shutdown
	mtuErrors   chan<- protocol.ByteCount
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn, mtuErrors chan<- protocol.ByteCount) sender {
	return &sendQueue{
		conn:        conn,
		mtuErrors:   mtuErrors,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	h.enqueue(queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn})
}

// SendMTUProbe sends a deliberately oversized discovery packet. A size error
// for this packet is expected evidence for the discoverer, not a data failure.
func (h *sendQueue) SendMTUProbe(p *packetBuffer, ecn protocol.ECN) {
	h.enqueue(queueEntry{buf: p, ecn: ecn, mtuProbe: true})
}

func (h *sendQueue) enqueue(entry queueEntry) {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	select {
	case <-h.runStopped:
		entry.buf.Release()
		return
	default:
	}
	select {
	case h.queue <- entry:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer h.stop()
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			if err := h.write(e); err != nil {
				return err
			}
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) write(entry queueEntry) error {
	defer entry.buf.Release()
	err := h.conn.Write(entry.buf.Data, entry.gsoSize, entry.ecn)
	var tooLarge *DatagramTooLargeError
	if err == nil || !isSendMsgSizeErr(err) && !errors.As(err, &tooLarge) {
		return err
	}
	if entry.mtuProbe {
		return nil
	}
	if h.reportMTUError(entry) {
		return nil
	}
	return fmt.Errorf("cannot send non-probe QUIC packet (%d bytes): %w", entry.buf.Len(), err)
}

func (h *sendQueue) reportMTUError(entry queueEntry) bool {
	size := entry.buf.Len()
	if entry.gsoSize != 0 {
		size = min(size, protocol.ByteCount(entry.gsoSize))
	}
	// A path that cannot carry QUIC's minimum size cannot be recovered by
	// reducing packet size. Preserve the error when no recovery owner exists.
	if size <= protocol.MinInitialPacketSize || h.mtuErrors == nil {
		return false
	}
	select {
	case h.mtuErrors <- size:
	default: // One pending notification suffices to fall back to the base size.
	}
	return true
}

func (h *sendQueue) stop() {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	close(h.runStopped)
	for {
		select {
		case entry := <-h.queue:
			entry.buf.Release()
		default:
			return
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
