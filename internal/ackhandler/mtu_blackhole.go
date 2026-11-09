package ackhandler

import "github.com/apernet/quic-go/internal/protocol"

const mtuBlackholeThreshold = 3

// This bounded observation belongs to one packet-size epoch on the active path.
// Only ordinary ack-eliciting 1-RTT packets contribute; PMTU and path probes do not.
type mtuLossState struct {
	firstPacket  protocol.PacketNumber
	lastAcked    protocol.PacketNumber
	lastAckSize  protocol.ByteCount
	lastLost     protocol.PacketNumber
	smallestLost protocol.ByteCount
	losses       uint8
}

func newMTULossState(first protocol.PacketNumber) mtuLossState {
	return mtuLossState{firstPacket: first, lastAcked: protocol.InvalidPacketNumber, lastLost: protocol.InvalidPacketNumber}
}

func (m *mtuLossState) acked(number protocol.PacketNumber, size protocol.ByteCount) {
	if number < m.firstPacket || number <= m.lastAcked || size <= protocol.MinInitialPacketSize {
		return
	}
	m.lastAcked, m.lastAckSize = number, size
	if number >= m.lastLost && size >= m.smallestLost {
		m.losses, m.smallestLost = 0, 0
	}
}

func (m *mtuLossState) lost(number protocol.PacketNumber, size protocol.ByteCount) {
	if number < m.firstPacket || number <= m.lastLost || size <= protocol.MinInitialPacketSize {
		return
	}
	if number < m.lastAcked && size <= m.lastAckSize {
		return // A later packet already demonstrated delivery at this size.
	}
	m.lastLost = number
	if m.losses == 0 || size < m.smallestLost {
		m.smallestLost = size
	}
	if m.losses < mtuBlackholeThreshold {
		m.losses++
	}
}

func ordinaryMTUData(p *packet) bool {
	return p.EncryptionLevel == protocol.Encryption1RTT && !p.IsPathMTUProbePacket && !p.isPathProbePacket && p.IsAckEliciting()
}

func (h *sentPacketHandler) observeMTUAcks(packets []packetWithPacketNumber) {
	for _, p := range packets {
		if ordinaryMTUData(p.packet) {
			h.mtuLoss.acked(p.PacketNumber, p.Length)
		}
	}
}

func (h *sentPacketHandler) MTUBlackholeSize() protocol.ByteCount {
	if h.mtuLoss.losses >= mtuBlackholeThreshold {
		return h.mtuLoss.smallestLost
	}
	// Without any ACKs the loss detector cannot declare newer packets lost.
	// Consecutive PTOs also require trying the validated QUIC base size.
	if h.ptoCount >= mtuBlackholeThreshold {
		return h.maxDatagramSize
	}
	return 0
}
