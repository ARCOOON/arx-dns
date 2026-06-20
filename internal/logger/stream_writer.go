package logger

import (
	"bytes"
	"sync"
)

// StreamWriter buffers newline-delimited JSON log lines and dispatches complete
// records to the in-memory ring buffer and live SSE broadcaster.
type StreamWriter struct {
	ring        *RingBuffer
	broadcaster *Broadcaster
	mu          sync.Mutex
	partial     []byte
}

// NewStreamWriter wires the UI/history log sinks together.
func NewStreamWriter(ring *RingBuffer, broadcaster *Broadcaster) *StreamWriter {
	return &StreamWriter{
		ring:        ring,
		broadcaster: broadcaster,
	}
}

// Write implements io.Writer. slog emits newline-terminated JSON records;
// partial writes are buffered until a full line is available.
func (s *StreamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := append(s.partial, p...)
	s.partial = nil

	for {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			s.partial = append([]byte(nil), data...)
			return len(p), nil
		}

		line := string(data[:idx])
		if line != "" {
			s.dispatch(line)
		}
		data = data[idx+1:]
	}
}

func (s *StreamWriter) dispatch(line string) {
	if s.ring != nil {
		s.ring.Append(line)
	}
	if s.broadcaster != nil {
		s.broadcaster.Publish(line)
	}
}
