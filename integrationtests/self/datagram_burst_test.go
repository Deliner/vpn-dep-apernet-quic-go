package self_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestNHOPConnectionDatagramBurst(t *testing.T) {
	for _, direction := range []string{"to-client", "to-server"} {
		t.Run(direction, func(t *testing.T) {
			client, server, clientEvents, serverEvents := datagramBurstPeers(t)
			sender, receiver, observed := server, client, clientEvents
			if direction == "to-server" {
				sender, receiver, observed = client, server, serverEvents
			}
			for sequence := range 256 {
				require.NoError(t, sender.SendDatagram(connectionBurstPacket(sequence)))
			}
			// PacketReceived is recorded after frame handling. Wait until the real
			// receiver processed every DATAGRAM before allowing its consumer to run.
			require.Eventually(t, func() bool { return receivedBurstFrames(observed) == 256 }, 5*time.Second, time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			seen := make(map[uint32]bool)
			for sequence := range 256 {
				data, err := receiver.ReceiveDatagram(ctx)
				require.NoError(t, err, "burst stopped at packet %d of 256", sequence)
				require.Len(t, data, 930)
				id := binary.BigEndian.Uint32(data)
				require.Less(t, id, uint32(256))
				require.False(t, seen[id], "duplicate datagram identity")
				require.Equal(t, connectionBurstPacket(int(id)), data)
				seen[id] = true
			}
		})
	}
}

func datagramBurstPeers(t *testing.T) (*quic.Conn, *quic.Conn, *events.Recorder, *events.Recorder) {
	t.Helper()
	clientEvents, serverEvents := &events.Recorder{}, &events.Recorder{}
	listener, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), datagramBurstConfig(t, serverEvents))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.Dial(ctx, newUDPConnLocalhost(t), listener.Addr(), getTLSClientConfig(), datagramBurstConfig(t, clientEvents))
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server, clientEvents, serverEvents
}

func datagramBurstConfig(t *testing.T, recorder *events.Recorder) *quic.Config {
	t.Helper()
	config := &quic.Config{EnableDatagrams: true, Tracer: newTracer(recorder)}
	// The same regression executes on the old library and fails after its
	// fixed 128-packet queue fills, rather than merely failing to compile.
	if configurable, ok := any(config).(interface{ SetDatagramReceiveBuffer(int, int) error }); ok {
		require.NoError(t, configurable.SetDatagramReceiveBuffer(1024, 1<<20))
	} else {
		t.Log("baseline: fixed QUIC connection receive queue")
	}
	return getQuicConfig(config)
}

func receivedBurstFrames(recorder *events.Recorder) int {
	count := 0
	for _, event := range recorder.Events(qlog.PacketReceived{}) {
		for _, frame := range event.(qlog.PacketReceived).Frames {
			if _, ok := frame.Frame.(*qlog.DatagramFrame); ok {
				count++
			}
		}
	}
	return count
}

func connectionBurstPacket(sequence int) []byte {
	data := bytes.Repeat([]byte{0x5a}, 930)
	binary.BigEndian.PutUint32(data, uint32(sequence))
	return data
}
