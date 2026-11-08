package http3

import "errors"

// SetDatagramReceiveBuffer sets the receive budget for this HTTP/3 stream only.
// Configure it before exchanging datagrams. The budget is bounded independently
// by packet count (1..4096) and payload bytes (1..16 MiB); allocation is lazy.
// Excess incoming datagrams are dropped. This does not provide reliable delivery
// or resize the underlying QUIC / kernel queues. Invalid limits, a closed receive
// side, or shrinking below already queued data return an error without changes.
func (s *Stream) SetDatagramReceiveBuffer(packets, bytes int) error {
	configurable, ok := s.datagramStream.(interface {
		SetDatagramReceiveBuffer(int, int) error
	})
	if !ok {
		return errors.New("http3: stream does not support a datagram receive budget")
	}
	return configurable.SetDatagramReceiveBuffer(packets, bytes)
}

// SetDatagramReceiveBuffer configures this request's receive budget. It has the
// same contract as Stream.SetDatagramReceiveBuffer and is safe before sending
// request headers, so an early response cannot fill a smaller default queue.
func (s *RequestStream) SetDatagramReceiveBuffer(packets, bytes int) error {
	return s.str.SetDatagramReceiveBuffer(packets, bytes)
}

func (s *stateTrackingStream) SetDatagramReceiveBuffer(packets, bytes int) error {
	s.mx.Lock()
	defer s.mx.Unlock()
	if s.recvErr != nil {
		return s.recvErr
	}
	return s.queue.configure(packets, bytes)
}
