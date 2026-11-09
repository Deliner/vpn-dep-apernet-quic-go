package quic

import (
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/qlog"
)

// The connection loop owns PMTU changes. The asynchronous writer only reports
// the size of rejected data; it never mutates packetization or congestion state.
func (c *Conn) initializeSendQueue() {
	c.sendMTUErrors = make(chan protocol.ByteCount, 1)
	c.sendQueue = newSendQueue(c.conn, c.sendMTUErrors)
}

func (c *Conn) handleMTUChanges(now monotime.Time) {
	select {
	case size := <-c.sendMTUErrors:
		c.reducePathMTU(now, size)
	default:
	}
	if c.mtuDiscoverer == nil || c.mtuDiscoverer.CurrentSize() <= protocol.MinInitialPacketSize {
		return
	}
	if size := c.sentPacketHandler.MTUBlackholeSize(); size > 0 {
		c.reducePathMTU(now, size)
	}
}

func (c *Conn) reducePathMTU(now monotime.Time, rejected protocol.ByteCount) {
	current := c.maxPacketSize()
	if rejected <= protocol.MinInitialPacketSize || current <= protocol.MinInitialPacketSize || rejected > current {
		return
	}
	const base = protocol.ByteCount(protocol.MinInitialPacketSize)
	if c.mtuDiscoverer == nil {
		c.initialPacketSize = base
	} else {
		ceiling := min(current-1, rejected-1)
		if c.config.DisablePathMTUDiscovery {
			ceiling = base
		}
		c.mtuDiscoverer.Reset(now, base, max(base, ceiling))
	}
	c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(base)))
	c.sentPacketHandler.SetMaxDatagramSize(base)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.MTUUpdated{Value: int(base), Done: c.config.DisablePathMTUDiscovery})
	}
	c.scheduleSending()
}
