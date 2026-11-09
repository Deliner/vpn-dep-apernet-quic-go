package quic

import (
	"net"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNHOPSendQueueDataSizeFailures(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"kernel", &net.OpError{Op: "write", Err: syscall.EMSGSIZE}},
		{"wrapped-transport", &DatagramTooLargeError{MaxDatagramPayloadSize: 1200}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { dataSizeFailure(t, failure.err) })
		})
	}
}

func dataSizeFailure(t *testing.T, failure error) {
	t.Helper()
	conn := NewMockSendConn(gomock.NewController(t))
	queue := newSendQueue(conn, nil)
	defer queue.Close()
	packet := getPacketWithContents(make([]byte, 1300))
	conn.EXPECT().Write(packet.Data, uint16(0), protocol.ECNNon).Return(failure)
	queue.Send(packet, 0, protocol.ECNNon)
	result := make(chan error, 1)
	go func() { result <- queue.Run() }()
	synctest.Wait()
	select {
	case err := <-result:
		require.ErrorIs(t, err, failure)
		require.Zero(t, packet.refCount, "failed writes must release their owned packet")
	default:
		t.Error("size failure of ordinary data must stop the connection instead of silently dropping the packet")
	}
}

func TestNHOPSendQueueMTUProbeSizeFailuresRemainNonfatal(t *testing.T) {
	for _, failure := range []error{
		&net.OpError{Op: "write", Err: syscall.EMSGSIZE},
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1200},
	} {
		synctest.Test(t, func(t *testing.T) { mtuProbeFailure(t, failure) })
	}
}

func mtuProbeFailure(t *testing.T, failure error) {
	t.Helper()
	conn := NewMockSendConn(gomock.NewController(t))
	queue := newSendQueue(conn, nil)
	probe := getPacketWithContents(make([]byte, 1400))
	data := getPacketWithContents([]byte("small data"))
	gomock.InOrder(
		conn.EXPECT().Write(probe.Data, uint16(0), protocol.ECT1).Return(failure),
		conn.EXPECT().Write(data.Data, uint16(0), protocol.ECNNon).Return(nil),
	)
	queue.SendMTUProbe(probe, protocol.ECT1)
	queue.Send(data, 0, protocol.ECNNon)
	result := make(chan error, 1)
	go func() { result <- queue.Run() }()
	synctest.Wait()
	select {
	case err := <-result:
		queue.Close()
		t.Fatalf("discovery size error terminated sender: %v", err)
	default:
	}
	queue.Close()
	require.NoError(t, <-result)
	require.Zero(t, probe.refCount)
	require.Zero(t, data.refCount)
}

func TestNHOPSendQueueFatalErrorReleasesOwnedBuffers(t *testing.T) {
	conn := NewMockSendConn(gomock.NewController(t))
	queue := newSendQueue(conn, nil)
	defer queue.Close()
	packets := make([]*packetBuffer, sendQueueCapacity)
	for index := range packets {
		packets[index] = getPacketWithContents([]byte("queued data"))
		queue.Send(packets[index], 0, protocol.ECNNon)
	}
	conn.EXPECT().Write(packets[0].Data, uint16(0), protocol.ECNNon).Return(assert.AnError)
	require.ErrorIs(t, queue.Run(), assert.AnError)
	for _, packet := range packets {
		require.Zero(t, packet.refCount, "failed and unattempted packets must return to the pool")
	}
	late := getPacketWithContents([]byte("late data"))
	queue.Send(late, 0, protocol.ECNNon)
	require.Zero(t, late.refCount, "ownership also transfers when the sender has stopped")
}

func TestNHOPSendQueueProbeOrdinaryErrorStillStopsSender(t *testing.T) {
	conn := NewMockSendConn(gomock.NewController(t))
	queue := newSendQueue(conn, nil)
	defer queue.Close()
	packet := getPacketWithContents([]byte("probe"))
	conn.EXPECT().Write(packet.Data, uint16(0), protocol.ECNNon).Return(assert.AnError)
	queue.SendMTUProbe(packet, protocol.ECNNon)
	require.ErrorIs(t, queue.Run(), assert.AnError)
	require.Zero(t, packet.refCount)
}

func TestNHOPSendQueueShutdownRacesWithPacketAdmission(t *testing.T) {
	for range 64 {
		synctest.Test(t, func(t *testing.T) { shutdownAdmission(t) })
	}
}

func shutdownAdmission(t *testing.T) {
	t.Helper()
	conn := NewMockSendConn(gomock.NewController(t))
	queue := newSendQueue(conn, nil)
	defer queue.Close()
	failed := getPacketWithContents([]byte("failed"))
	queued := getPacketWithContents([]byte("queued"))
	late := getPacketWithContents([]byte("racing"))
	ready, release, admitted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	conn.EXPECT().Write(failed.Data, uint16(0), protocol.ECNNon).DoAndReturn(
		func([]byte, uint16, protocol.ECN) error {
			close(ready)
			<-release
			return assert.AnError
		},
	)
	queue.Send(failed, 0, protocol.ECNNon)
	queue.Send(queued, 0, protocol.ECNNon)
	result := make(chan error, 1)
	go func() { result <- queue.Run() }()
	<-ready
	go func() {
		<-release
		queue.Send(late, 0, protocol.ECNNon)
		close(admitted)
	}()
	close(release)
	synctest.Wait()
	require.ErrorIs(t, <-result, assert.AnError)
	<-admitted
	for _, packet := range []*packetBuffer{failed, queued, late} {
		require.Zero(t, packet.refCount)
	}
}
