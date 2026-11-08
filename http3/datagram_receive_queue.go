package http3

import "fmt"

const (
	streamDatagramQueueLen  = 32
	maxDatagramQueuePackets = 4096
	maxDatagramQueueBytes   = 16 << 20
)

// datagramReceiveQueue is owned by stateTrackingStream.mx. Both limits are
// necessary: a byte-only limit permits an unbounded number of empty datagrams.
// Its zero value preserves the existing 32-packet receive policy.
type datagramReceiveQueue struct {
	slots      [][]byte
	head       int
	count      int
	bytes      int
	maxPackets int
	maxBytes   int
}

func (q *datagramReceiveQueue) limits() (packets, bytes int) {
	if q.maxPackets == 0 {
		return streamDatagramQueueLen, streamDatagramQueueLen * 65535
	}
	return q.maxPackets, q.maxBytes
}

func (q *datagramReceiveQueue) configure(packets, bytes int) error {
	if packets < 1 || packets > maxDatagramQueuePackets || bytes < 1 || bytes > maxDatagramQueueBytes {
		return fmt.Errorf("http3: datagram receive budget must be 1..%d packets and 1..%d bytes", maxDatagramQueuePackets, maxDatagramQueueBytes)
	}
	if q.count > packets || q.bytes > bytes {
		return fmt.Errorf("http3: datagram receive budget is smaller than the queued payload")
	}
	q.maxPackets, q.maxBytes = packets, bytes
	if len(q.slots) > packets {
		q.resize(packets)
	}
	return nil
}

func (q *datagramReceiveQueue) push(data []byte) bool {
	packets, bytes := q.limits()
	if q.count >= packets || len(data) > bytes-q.bytes {
		return false
	}
	if q.count == len(q.slots) {
		q.resize(min(packets, max(4, 2*len(q.slots))))
	}
	tail := (q.head + q.count) % len(q.slots)
	q.slots[tail] = data
	q.count++
	q.bytes += len(data)
	return true
}

func (q *datagramReceiveQueue) pop() ([]byte, bool) {
	if q.count == 0 {
		return nil, false
	}
	data := q.slots[q.head]
	q.slots[q.head] = nil
	q.head = (q.head + 1) % len(q.slots)
	q.count--
	q.bytes -= len(data)
	return data, true
}

func (q *datagramReceiveQueue) resize(capacity int) {
	slots := make([][]byte, capacity)
	for i := range q.count {
		slots[i] = q.slots[(q.head+i)%len(q.slots)]
	}
	q.slots, q.head = slots, 0
}
