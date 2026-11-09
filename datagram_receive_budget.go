package quic

import "fmt"

const (
	maxDatagramRcvQueueLen    = 128
	maxDatagramReceivePackets = 4096
	maxDatagramReceiveBytes   = 16 << 20
)

// A receive budget belongs to one connection. Both limits are required because
// byte limits alone do not bound the number of empty DATAGRAM frames.
type datagramReceiveBudget struct {
	packets int
	bytes   int
}

func newDatagramReceiveBudget(packets, bytes int) (datagramReceiveBudget, error) {
	if packets < 1 || packets > maxDatagramReceivePackets || bytes < 1 || bytes > maxDatagramReceiveBytes {
		return datagramReceiveBudget{}, fmt.Errorf("quic: datagram receive budget must be 1..%d packets and 1..%d bytes", maxDatagramReceivePackets, maxDatagramReceiveBytes)
	}
	return datagramReceiveBudget{packets: packets, bytes: bytes}, nil
}

func (b datagramReceiveBudget) limits() (packets, bytes int) {
	if b.packets == 0 {
		// Preserve the legacy 128-packet budget for applications that don't opt
		// in. 65535 bounds any frame that can fit in one UDP datagram.
		return maxDatagramRcvQueueLen, maxDatagramRcvQueueLen * 65535
	}
	return b.packets, b.bytes
}
