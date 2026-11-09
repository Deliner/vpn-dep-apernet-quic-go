package quic

import (
	"net"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNHOPSendQueueReportsMTUWithoutBlocking(t *testing.T) {
	for _, failure := range []error{
		&net.OpError{Op: "write", Err: syscall.EMSGSIZE},
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1252},
	} {
		synctest.Test(t, func(t *testing.T) { verifyMTUFeedback(t, failure) })
	}
}

func verifyMTUFeedback(t *testing.T, failure error) {
	t.Helper()
	conn := NewMockSendConn(gomock.NewController(t))
	feedback := make(chan protocol.ByteCount, 1)
	queue := newSendQueue(conn, feedback)
	batch := getLargePacketBuffer()
	batch.Data = batch.Data[:2800]
	packets := []*packetBuffer{batch, getPacketWithContents(make([]byte, 1308)), getPacketWithContents(make([]byte, 900))}
	gomock.InOrder(
		conn.EXPECT().Write(packets[0].Data, uint16(1400), protocol.ECNNon).Return(failure),
		conn.EXPECT().Write(packets[1].Data, uint16(1439), protocol.ECNNon).Return(failure),
		conn.EXPECT().Write(packets[2].Data, uint16(0), protocol.ECNNon).Return(nil),
	)
	queue.Send(packets[0], 1400, protocol.ECNNon)
	queue.Send(packets[1], 1439, protocol.ECNNon)
	queue.Send(packets[2], 0, protocol.ECNNon)
	result := make(chan error, 1)
	go func() { result <- queue.Run() }()
	synctest.Wait()
	queue.Close()
	require.NoError(t, <-result, "a full feedback slot must not block valid smaller packets")
	require.Equal(t, protocol.ByteCount(1400), <-feedback, "GSO reports one segment, not the batch")
	require.Empty(t, feedback, "pending notifications must be coalesced")
	for _, packet := range packets {
		require.Zero(t, packet.refCount)
	}
}

func TestNHOPSendQueueMinimumMTUFailureIsFatal(t *testing.T) {
	conn := NewMockSendConn(gomock.NewController(t))
	feedback := make(chan protocol.ByteCount, 1)
	queue := newSendQueue(conn, feedback)
	defer queue.Close()
	packet := getLargePacketBuffer()
	packet.Data = packet.Data[:2400]
	failure := &net.OpError{Op: "write", Err: syscall.EMSGSIZE}
	conn.EXPECT().Write(packet.Data, uint16(1200), protocol.ECNNon).Return(failure)
	queue.Send(packet, 1200, protocol.ECNNon)
	require.ErrorIs(t, queue.Run(), failure)
	require.Empty(t, feedback)
	require.Zero(t, packet.refCount)
}

func TestNHOPSendQueueShortGSOSegmentFeedback(t *testing.T) {
	conn := NewMockSendConn(gomock.NewController(t))
	feedback := make(chan protocol.ByteCount, 1)
	queue := newSendQueue(conn, feedback).(*sendQueue)
	packet := getPacketWithContents(make([]byte, 1308))
	defer packet.Release()
	require.True(t, queue.reportMTUError(queueEntry{buf: packet, gsoSize: 1439}))
	require.Equal(t, protocol.ByteCount(1308), <-feedback)
}
