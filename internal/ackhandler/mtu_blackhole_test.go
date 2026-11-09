package ackhandler

import (
	"testing"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestNHOPMTULossEvidenceRequiresRepeatedUnsupportedSize(t *testing.T) {
	h := &sentPacketHandler{maxDatagramSize: 1452, mtuLoss: newMTULossState(10)}
	h.mtuLoss.lost(9, 1400) // previous size epoch
	h.mtuLoss.lost(10, 1200)
	h.mtuLoss.lost(11, 1308)
	h.mtuLoss.lost(11, 1308) // duplicate observation
	h.mtuLoss.lost(12, 1400)
	require.Zero(t, h.MTUBlackholeSize())
	h.mtuLoss.acked(13, 1252) // delivery below the lost sizes is insufficient
	h.mtuLoss.lost(14, 1308)
	require.Equal(t, protocol.ByteCount(1308), h.MTUBlackholeSize())
	h.mtuLoss.acked(15, 1400)
	require.Zero(t, h.MTUBlackholeSize(), "later delivery disproves the suspected size black hole")
	h.mtuLoss.lost(13, 1308) // delayed loss older than successful large delivery
	require.Zero(t, h.MTUBlackholeSize())
	for pn := protocol.PacketNumber(16); pn < 1000; pn++ {
		h.mtuLoss.lost(pn, 1400)
	}
	require.Equal(t, uint8(mtuBlackholeThreshold), h.mtuLoss.losses, "counter must saturate")
}

func TestNHOPMTUBlackholePTOAndEpoch(t *testing.T) {
	h := &sentPacketHandler{maxDatagramSize: 1400, mtuLoss: newMTULossState(1)}
	h.ptoCount = 2
	require.Zero(t, h.MTUBlackholeSize())
	h.ptoCount = 3
	require.Equal(t, protocol.ByteCount(1400), h.MTUBlackholeSize())
	h.ptoCount = 0
	for pn := protocol.PacketNumber(1); pn <= 3; pn++ {
		h.mtuLoss.lost(pn, 1300)
	}
	require.Equal(t, protocol.ByteCount(1300), h.MTUBlackholeSize())
	h.mtuLoss = newMTULossState(20)
	h.mtuLoss.lost(19, 1400)
	h.mtuLoss.acked(18, 1400)
	require.Zero(t, h.MTUBlackholeSize(), "old callbacks must not affect a new size epoch")
}

func TestNHOPMTUEvidenceExcludesACKOnlyAndProbePackets(t *testing.T) {
	p := &packet{EncryptionLevel: protocol.Encryption1RTT, Frames: []Frame{{Frame: &wire.PingFrame{}}}}
	require.True(t, ordinaryMTUData(p))
	p.IsPathMTUProbePacket = true
	require.False(t, ordinaryMTUData(p))
	p.IsPathMTUProbePacket, p.isPathProbePacket = false, true
	require.False(t, ordinaryMTUData(p))
	p.isPathProbePacket, p.EncryptionLevel = false, protocol.Encryption0RTT
	require.False(t, ordinaryMTUData(p))
	p.EncryptionLevel, p.Frames = protocol.Encryption1RTT, nil
	require.False(t, ordinaryMTUData(p))
	p.Frames = []Frame{{Frame: &wire.DatagramFrame{Data: []byte("data")}}}
	require.True(t, ordinaryMTUData(p), "unreliable DATAGRAM packets still supply size evidence")
}

func TestNHOPMTUMigrationStartsNewSizeEpoch(t *testing.T) {
	h := NewSentPacketHandler(0, 1400, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	var tracker packetTracker
	now := monotime.Now()
	var last protocol.PacketNumber
	for range 3 {
		last = h.PopPacketNumber(protocol.Encryption1RTT)
		h.SentPacket(now, last, protocol.InvalidPacketNumber, nil, []Frame{tracker.NewPingFrame(last)}, protocol.Encryption1RTT, protocol.ECNNon, 1300, false, false)
		h.mtuLoss.lost(last, 1300)
	}
	require.Equal(t, protocol.ByteCount(1300), h.MTUBlackholeSize())
	h.MigratedPath(now, 1252)
	require.Equal(t, protocol.ByteCount(1252), h.maxDatagramSize)
	h.mtuLoss.lost(last, 1300)
	h.mtuLoss.acked(last, 1400)
	require.Zero(t, h.MTUBlackholeSize())
	h.ptoCount = 3
	require.Equal(t, protocol.ByteCount(1252), h.MTUBlackholeSize())
}
