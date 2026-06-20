package logger

import "sync"

const defaultRingCapacity = 500

// RingBuffer stores the most recent log lines in a fixed-size circular buffer.
type RingBuffer struct {
	mu       sync.RWMutex
	lines    []string
	capacity int
	head     int
	size     int
}

// NewRingBuffer creates a ring buffer that retains up to capacity log lines.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = defaultRingCapacity
	}
	return &RingBuffer{
		lines:    make([]string, capacity),
		capacity: capacity,
	}
}

// Append stores one log line, evicting the oldest entry when full.
func (r *RingBuffer) Append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines[r.head] = line
	r.head = (r.head + 1) % r.capacity
	if r.size < r.capacity {
		r.size++
	}
}

// Snapshot returns all stored lines in chronological order.
func (r *RingBuffer) Snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.size == 0 {
		return nil
	}

	out := make([]string, r.size)
	start := r.head - r.size
	if start < 0 {
		start += r.capacity
	}
	for i := 0; i < r.size; i++ {
		out[i] = r.lines[(start+i)%r.capacity]
	}
	return out
}
