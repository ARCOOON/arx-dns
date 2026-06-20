package logger

import "sync"

const subscriberBuffer = 64

// Broadcaster fans out new log lines to active SSE subscribers.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan string]struct{}
}

// NewBroadcaster creates an empty log line broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan string]struct{}),
	}
}

// Subscribe registers a new subscriber channel. The caller must call Unsubscribe
// when the consumer disconnects to avoid retaining unused channels.
func (b *Broadcaster) Subscribe() chan string {
	ch := make(chan string, subscriberBuffer)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel from the broadcaster and closes it
// after draining any buffered lines so disconnected clients do not leak memory.
func (b *Broadcaster) Unsubscribe(ch chan string) {
	if ch == nil {
		return
	}
	b.mu.Lock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
	}
	b.mu.Unlock()

	for {
		select {
		case <-ch:
		default:
			close(ch)
			return
		}
	}
}

// Publish delivers a log line to all subscribers without blocking the writer.
func (b *Broadcaster) Publish(line string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}
