package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func budgetedDatagramQueue(t *testing.T, packets, bytes int) *datagramQueue {
	t.Helper()
	config := &Config{}
	require.NoError(t, config.SetDatagramReceiveBuffer(packets, bytes))
	return newDatagramQueue(func() {}, utils.DefaultLogger, config)
}

func TestNHOPDatagramReceiveBudgetBounds(t *testing.T) {
	queue := budgetedDatagramQueue(t, 3, 6)
	for range 2 {
		queue.HandleDatagramFrame(&wire.DatagramFrame{})
	}
	data := []byte("abcdef")
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
	data[0] = 'x'
	queue.HandleDatagramFrame(&wire.DatagramFrame{})
	require.Equal(t, 3, queue.rcvQueue.Len(), "empty frames must consume packet budget")
	for range 2 {
		received, err := queue.Receive(context.Background())
		require.NoError(t, err)
		require.Empty(t, received)
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("g")})
	require.Equal(t, 1, queue.rcvQueue.Len(), "byte budget must reject despite free packet slots")
	require.Equal(t, 6, queue.rcvBytes)
	received, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("abcdef"), received, "caller must not own queued bytes")
	require.Zero(t, queue.rcvBytes)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("ghijkl")})
	queue.CloseWithError(io.EOF)
	received, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("ghijkl"), received)
	_, err = queue.Receive(context.Background())
	require.ErrorIs(t, err, io.EOF)
}

func TestNHOPDatagramReceiveBudgetRejectsWithoutAllocation(t *testing.T) {
	for _, full := range []bool{false, true} {
		queue := budgetedDatagramQueue(t, 1, 4)
		if full {
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("full")})
		}
		frame := &wire.DatagramFrame{Data: make([]byte, 65535)}
		allocations := testing.AllocsPerRun(100, func() { queue.HandleDatagramFrame(frame) })
		require.Zero(t, allocations, "rejected frames must not allocate payload copies")
	}
}

func TestNHOPDatagramReceiveRingWrap(t *testing.T) {
	queue := budgetedDatagramQueue(t, 17, 34)
	for sequence := range 12 {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(sequence), 0}})
	}
	for sequence := range 8 {
		data, err := queue.Receive(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{byte(sequence), 0}, data)
	}
	for sequence := 12; sequence < 26; sequence++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(sequence), 0}})
	}
	require.Equal(t, 17, queue.rcvQueue.Len())
	require.Equal(t, 34, queue.rcvBytes)
	for sequence := 8; sequence < 25; sequence++ {
		data, err := queue.Receive(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{byte(sequence), 0}, data)
	}
	require.Zero(t, queue.rcvBytes)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := queue.Receive(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestNHOPDatagramReceiveBudgetConcurrentUse(t *testing.T) {
	queue := budgetedDatagramQueue(t, 1024, 1<<20)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sequence := range 1000 {
			data := queuedBurstPacket(sequence)
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
			data[0] = 0xff
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for sequence := range 1000 {
		data, err := queue.Receive(ctx)
		require.NoError(t, err)
		require.Equal(t, queuedBurstPacket(sequence), data)
	}
	<-done
	require.Zero(t, queue.rcvBytes)
	require.True(t, queue.rcvQueue.Empty())
}

func queuedBurstPacket(sequence int) []byte {
	data := bytes.Repeat([]byte{0x5a}, 930)
	binary.BigEndian.PutUint32(data, uint32(sequence))
	return data
}
