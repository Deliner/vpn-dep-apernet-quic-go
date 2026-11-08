package http3

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDatagramBurstWithinConfiguredBudget(t *testing.T) {
	client, _ := newStreamPair(t)
	stream := newStateTrackingStream(client, &mockStreamClearer{}, nil)
	// The old implementation has no configurable budget. Running the same burst
	// there establishes the 32-packet loss baseline without a compile-only failure.
	if configurable, ok := any(stream).(interface{ SetDatagramReceiveBuffer(int, int) error }); ok {
		require.NoError(t, configurable.SetDatagramReceiveBuffer(1024, 1<<20))
	} else {
		t.Log("baseline: fixed HTTP/3 receive queue")
	}
	for sequence := range 256 {
		stream.enqueueDatagram(burstDatagram(sequence))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for sequence := range 256 {
		data, err := stream.ReceiveDatagram(ctx)
		require.NoError(t, err, "burst stopped at packet %d of 256", sequence)
		require.Equal(t, burstDatagram(sequence), data)
	}
}

func burstDatagram(sequence int) []byte {
	data := bytes.Repeat([]byte{0x5a}, 900)
	binary.BigEndian.PutUint32(data, uint32(sequence))
	return data
}

func TestDatagramReceiveBudgetCountsEmptyPackets(t *testing.T) {
	var queue datagramReceiveQueue
	require.NoError(t, queue.configure(3, 6))
	for range 3 {
		require.True(t, queue.push(nil))
	}
	require.False(t, queue.push(nil))
	data, ok := queue.pop()
	require.True(t, ok)
	require.Nil(t, data)
	require.True(t, queue.push([]byte("sixsix")))
	require.False(t, queue.push([]byte("x")))
}

func TestDatagramReceiveByteLimitAndRejectedResize(t *testing.T) {
	var queue datagramReceiveQueue
	require.NoError(t, queue.configure(8, 6))
	require.True(t, queue.push([]byte("abc")))
	require.True(t, queue.push([]byte("def")))
	require.False(t, queue.push([]byte("g")))
	require.Error(t, queue.configure(1, 6))
	require.Error(t, queue.configure(8, 5))
	packets, bytes := queue.limits()
	require.Equal(t, 8, packets)
	require.Equal(t, 6, bytes)
	data, ok := queue.pop()
	require.True(t, ok)
	require.Equal(t, []byte("abc"), data)
	require.True(t, queue.push([]byte("xyz")))
	for _, want := range []string{"def", "xyz"} {
		data, ok := queue.pop()
		require.True(t, ok)
		require.Equal(t, want, string(data))
	}
	require.Zero(t, queue.bytes)
	for _, slot := range queue.slots {
		require.Nil(t, slot, "dequeued payload retained by its backing array")
	}
}

func TestDatagramReceiveRingPreservesOrderAcrossGrowthAndShrink(t *testing.T) {
	var queue datagramReceiveQueue
	require.NoError(t, queue.configure(17, 17))
	for i := range 7 {
		require.True(t, queue.push([]byte{byte(i)}))
	}
	for i := range 5 {
		data, ok := queue.pop()
		require.True(t, ok)
		require.Equal(t, []byte{byte(i)}, data)
	}
	for i := 7; i < 22; i++ {
		require.True(t, queue.push([]byte{byte(i)}))
	}
	require.False(t, queue.push([]byte{22}))
	data, ok := queue.pop()
	require.True(t, ok)
	require.Equal(t, []byte{5}, data)
	require.NoError(t, queue.configure(16, 16))
	for i := 6; i < 22; i++ {
		data, ok := queue.pop()
		require.True(t, ok)
		require.Equal(t, []byte{byte(i)}, data)
	}
	_, ok = queue.pop()
	require.False(t, ok)
	require.Zero(t, queue.bytes)
}

func TestDatagramReceiveBudgetRejectsInvalidBounds(t *testing.T) {
	var queue datagramReceiveQueue
	for _, limits := range [][2]int{{0, 1}, {-1, 1}, {1, 0}, {1, -1}, {4097, 1}, {1, 16<<20 + 1}, {math.MaxInt, math.MaxInt}} {
		require.Error(t, queue.configure(limits[0], limits[1]))
	}
	packets, bytes := queue.limits()
	require.Equal(t, 32, packets)
	require.Equal(t, 32*65535, bytes)
	require.Nil(t, queue.slots)
}

func TestDatagramReceiveBudgetIsPerStreamAndPubliclyReachable(t *testing.T) {
	client, server := newStreamPair(t)
	configured := newStateTrackingStream(client, &mockStreamClearer{}, nil)
	unchanged := newStateTrackingStream(server, &mockStreamClearer{}, nil)
	stream := &Stream{datagramStream: configured}
	request := &RequestStream{str: stream}
	require.NoError(t, request.SetDatagramReceiveBuffer(128, 1<<20))
	for i := range 64 {
		configured.enqueueDatagram(burstDatagram(i))
		unchanged.enqueueDatagram(burstDatagram(i))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, item := range []struct {
		stream *stateTrackingStream
		count  int
	}{{configured, 64}, {unchanged, 32}} {
		for i := range item.count {
			data, err := item.stream.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, burstDatagram(i), data)
		}
		_, err := item.stream.ReceiveDatagram(canceledCtx())
		require.ErrorIs(t, err, context.Canceled)
	}
	configured.closeReceive(io.EOF)
	require.ErrorIs(t, stream.SetDatagramReceiveBuffer(256, 1<<20), io.EOF)
	packets, _ := configured.queue.limits()
	require.Equal(t, 128, packets)
	require.Error(t, (&Stream{}).SetDatagramReceiveBuffer(128, 1<<20))
}

func TestDatagramReceiveBudgetConcurrentUse(t *testing.T) {
	client, _ := newStreamPair(t)
	stream := newStateTrackingStream(client, &mockStreamClearer{}, nil)
	require.NoError(t, stream.SetDatagramReceiveBuffer(1024, 1<<20))
	done := make(chan error, 2)
	go func() {
		for i := range 1000 {
			stream.enqueueDatagram(burstDatagram(i))
		}
		done <- nil
	}()
	go func() {
		for range 1000 {
			if err := stream.SetDatagramReceiveBuffer(1024, 1<<20); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := range 1000 {
		data, err := stream.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, burstDatagram(i), data)
	}
	for range 2 {
		require.NoError(t, <-done)
	}
}
