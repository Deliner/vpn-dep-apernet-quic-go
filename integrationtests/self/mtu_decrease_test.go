package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

func TestNHOPPathMTUDecrease(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, mode := range []string{"kernel", "blackhole"} {
			for _, direction := range []string{"client", "server"} {
				t.Run(network+"/"+mode+"/"+direction, func(t *testing.T) {
					runMTUDecrease(t, network, mode, direction)
				})
			}
		}
	}
}

func runMTUDecrease(t *testing.T, network, mode, direction string) {
	client, server, clientPath, serverPath := mtuDecreasePeers(t, mode, network)
	sender, receiver, path := client, server, clientPath
	if direction == "server" {
		sender, receiver, path = server, client, serverPath
	}
	limit := int64(1252) // IP MTU 1280, excluding IP and UDP headers.
	if network == "udp6" {
		limit = 1232
	}
	payload := bytes.Repeat([]byte{0x5c, 0xa3}, 128<<10)
	require.NoError(t, transferMTUData(sender, receiver, payload))
	require.GreaterOrEqual(t, path.largest.Load(), int64(1400))
	path.limit.Store(limit)
	err := transferMTUData(sender, receiver, payload)
	t.Logf("limit=%d rejected=%d connection_error=%v", limit, path.rejected.Load(), context.Cause(sender.Context()))
	require.Positive(t, path.rejected.Load(), "test never exercised the changed path")
	require.NoError(t, err, "existing connection did not survive the MTU decrease")
	require.NoError(t, context.Cause(sender.Context()))
	var tooLarge *quic.DatagramTooLargeError
	require.ErrorAs(t, sender.SendDatagram(make([]byte, 2000)), &tooLarge)
	require.Greater(t, tooLarge.MaxDatagramPayloadSize, int64(1100))
	require.LessOrEqual(t, tooLarge.MaxDatagramPayloadSize, limit)
	require.NoError(t, transferMTUData(receiver, sender, payload))
	transferMTUDatagrams(t, sender, receiver)
	transferMTUDatagrams(t, receiver, sender)
}

func mtuDecreasePeers(t *testing.T, mode, network string) (*quic.Conn, *quic.Conn, *mtuBoundConn, *mtuBoundConn) {
	t.Helper()
	clientPath, serverPath := newMTUBoundConn(t, mode, network), newMTUBoundConn(t, mode, network)
	config := func() *quic.Config {
		return getQuicConfig(&quic.Config{InitialPacketSize: 1400, EnableDatagrams: true})
	}
	listener, err := quic.Listen(serverPath, getTLSConfig(), config())
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.Dial(ctx, clientPath, listener.Addr(), getTLSClientConfig(), config())
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server, clientPath, serverPath
}

func transferMTUData(sender, receiver *quic.Conn, expected []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := sender.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	stream.SetWriteDeadline(deadline)
	written := make(chan error, 1)
	go func() {
		_, err := stream.Write(expected)
		if err == nil {
			err = stream.Close()
		}
		written <- err
	}()
	actual, err := receiveMTUData(ctx, receiver, deadline)
	stream.CancelWrite(0)
	writeErr := <-written
	if err != nil {
		return fmt.Errorf("receive: %w", err)
	}
	if writeErr != nil {
		return fmt.Errorf("write: %w", writeErr)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("payload mismatch: received %d of %d bytes", len(actual), len(expected))
	}
	return nil
}

func receiveMTUData(ctx context.Context, receiver *quic.Conn, deadline time.Time) ([]byte, error) {
	stream, err := receiver.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(0)
	stream.SetReadDeadline(deadline)
	return io.ReadAll(stream)
}

func transferMTUDatagrams(t *testing.T, sender, receiver *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for sequence := range 16 {
		expected := bytes.Repeat([]byte{0xa7}, 900)
		expected[0] = byte(sequence)
		require.NoError(t, sender.SendDatagram(expected))
		actual, err := receiver.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}
