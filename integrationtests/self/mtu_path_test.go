package self_test

import (
	"net"
	"sync/atomic"
	"syscall"
	"testing"
)

// This adapter leaves QUIC and real loopback UDP intact. Only the outer path's
// size contract changes; no host route, socket option or firewall is changed.
type mtuBoundConn struct {
	net.PacketConn
	mode     string
	limit    atomic.Int64
	rejected atomic.Int64
	largest  atomic.Int64
}

func newMTUBoundConn(t *testing.T, mode, network string) *mtuBoundConn {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "udp6" {
		address = "[::1]:0"
	}
	socket, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	conn := &mtuBoundConn{PacketConn: socket, mode: mode}
	conn.limit.Store(1500)
	return conn
}

func (c *mtuBoundConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if int64(len(data)) > c.limit.Load() {
		c.rejected.Add(1)
		if c.mode == "kernel" {
			return 0, &net.OpError{Op: "write", Net: "udp", Source: c.LocalAddr(), Addr: addr, Err: syscall.EMSGSIZE}
		}
		return len(data), nil // Packet lost in transit, without ICMP feedback.
	}
	for previous := c.largest.Load(); int64(len(data)) > previous; previous = c.largest.Load() {
		if c.largest.CompareAndSwap(previous, int64(len(data))) {
			break
		}
	}
	return c.PacketConn.WriteTo(data, addr)
}
