package dnsproc

import (
	"log/slog"
	"net"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const notifyWriteTimeout = 2 * time.Second

// ZoneChangeNotifier broadcasts RFC 1996 NOTIFY messages to configured slaves.
type ZoneChangeNotifier interface {
	NotifyZone(origin string)
	NotifyZones(origins []string)
}

// Notifier sends NOTIFY queries to slave nameservers when zones change.
type Notifier struct {
	enabled bool
	slaves  []string
	source  string
	stats   *telemetry.Stats
	logger  *slog.Logger
}

// NewNotifier creates a NOTIFY engine from configuration. When zone transfer is
// disabled or no slaves are configured, NotifyZone is a no-op.
func NewNotifier(enabled bool, slaves []string, sourceAddr string, stats *telemetry.Stats, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{
		enabled: enabled && len(slaves) > 0,
		slaves:  append([]string(nil), slaves...),
		source:  sourceAddr,
		stats:   stats,
		logger:  logger,
	}
}

// NotifyZone sends NOTIFY for a single zone origin.
func (n *Notifier) NotifyZone(origin string) {
	if n == nil || !n.enabled {
		return
	}
	origin = storage.NormalizeName(origin)
	if origin == "." {
		return
	}
	n.notify(origin)
}

// NotifyZones sends NOTIFY for each distinct zone origin.
func (n *Notifier) NotifyZones(origins []string) {
	if n == nil || !n.enabled || len(origins) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = storage.NormalizeName(origin)
		if origin == "." {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		n.notify(origin)
	}
}

func (n *Notifier) notify(origin string) {
	var wg sync.WaitGroup
	for _, slave := range n.slaves {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			n.sendNotify(origin, target)
		}(slave)
	}
	wg.Wait()
}

func (n *Notifier) sendNotify(origin, target string) {
	msg := new(mdns.Msg)
	msg.Id = mdns.Id()
	msg.Opcode = mdns.OpcodeNotify
	msg.Authoritative = true
	msg.Question = []mdns.Question{{
		Name:   origin,
		Qtype:  mdns.TypeSOA,
		Qclass: mdns.ClassINET,
	}}

	payload, err := msg.Pack()
	if err != nil {
		if n.logger != nil {
			n.logger.Warn("failed to pack NOTIFY message",
				"zone", origin,
				"slave", target,
				"error", err,
			)
		}
		if n.stats != nil {
			n.stats.IncNotifyFailed()
		}
		return
	}

	conn, err := net.DialTimeout("udp", target, notifyWriteTimeout)
	if err != nil {
		if n.logger != nil {
			n.logger.Warn("NOTIFY delivery failed",
				"zone", origin,
				"slave", target,
				"error", err,
			)
		}
		if n.stats != nil {
			n.stats.IncNotifyFailed()
		}
		return
	}
	defer conn.Close()

	if n.source != "" {
		_ = conn.(*net.UDPConn).SetWriteDeadline(time.Now().Add(notifyWriteTimeout))
	}

	if _, err := conn.Write(payload); err != nil {
		if n.logger != nil {
			n.logger.Warn("NOTIFY write failed",
				"zone", origin,
				"slave", target,
				"error", err,
			)
		}
		if n.stats != nil {
			n.stats.IncNotifyFailed()
		}
		return
	}

	if n.stats != nil {
		n.stats.IncNotifySent()
	}
	if n.logger != nil {
		n.logger.Info("NOTIFY sent",
			"zone", origin,
			"slave", target,
		)
	}
}
