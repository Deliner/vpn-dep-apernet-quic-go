package quic

import (
	"testing"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestNHOPMTUReductionBeforeHandshakeKeepsConfigPrivate(t *testing.T) {
	config := &Config{InitialPacketSize: 1400}
	c := newClientTestConnection(t, nil, config, false).conn
	c.reducePathMTU(monotime.Now(), 1400)
	require.Equal(t, protocol.ByteCount(1200), c.maxPacketSize())
	require.Equal(t, uint16(1400), config.InitialPacketSize)
	require.Equal(t, uint16(1400), c.config.InitialPacketSize)
	require.Equal(t, uint32(estimateMaxPayloadSize(1200)), c.maxPayloadSizeEstimate.Load())
}

func TestNHOPMTUReductionUpdatesAllSendLimits(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		config := &Config{InitialPacketSize: 1400, DisablePathMTUDiscovery: disabled}
		c := newClientTestConnection(t, nil, config, false).conn
		recorder := &events.Recorder{}
		c.qlogger = recorder
		finder := newMTUDiscoverer(utils.NewRTTStats(), 1400, 1500, nil)
		c.mtuDiscoverer = finder
		c.reducePathMTU(monotime.Now(), 1308)
		require.Equal(t, protocol.ByteCount(1200), c.maxPacketSize())
		require.Equal(t, uint32(estimateMaxPayloadSize(1200)), c.maxPayloadSizeEstimate.Load())
		require.Equal(t, disabled, finder.done())
		require.Less(t, finder.max(), protocol.ByteCount(1308))
		require.Equal(t, []int{1200}, mtuEventSizes(recorder))
		c.reducePathMTU(monotime.Now(), 1400) // delayed notification from old queue entries
		require.Equal(t, []int{1200}, mtuEventSizes(recorder))
	}
}

func TestNHOPMTUEpochDoesNotWrapAfterRepeatedReduction(t *testing.T) {
	now := monotime.Now()
	finder := newMTUDiscoverer(utils.NewRTTStats(), 1200, 1500, nil)
	probe, _ := finder.GetPing(now)
	for range 256 {
		finder.Reset(now, 1200, 1252)
	}
	require.NotPanics(t, func() { probe.Handler.OnAcked(probe.Frame) })
	require.NotPanics(t, func() { probe.Handler.OnLost(probe.Frame) })
	require.Equal(t, protocol.ByteCount(1200), finder.CurrentSize())
}

func TestNHOPMTUReductionIgnoresOldLargerPackets(t *testing.T) {
	c := newClientTestConnection(t, nil, &Config{InitialPacketSize: 1400}, false).conn
	c.mtuDiscoverer = newMTUDiscoverer(utils.NewRTTStats(), 1252, 1300, nil)
	c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(1252)))
	recorder := &events.Recorder{}
	c.qlogger = recorder
	c.reducePathMTU(monotime.Now(), 1400)
	require.Equal(t, protocol.ByteCount(1252), c.maxPacketSize())
	require.Equal(t, uint32(estimateMaxPayloadSize(1252)), c.maxPayloadSizeEstimate.Load())
	require.Empty(t, recorder.Events(qlog.MTUUpdated{}))
}

func mtuEventSizes(recorder *events.Recorder) []int {
	var sizes []int
	for _, event := range recorder.Events(qlog.MTUUpdated{}) {
		sizes = append(sizes, event.(qlog.MTUUpdated).Value)
	}
	return sizes
}
