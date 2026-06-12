package dnsproc

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const defaultUpstreamTimeout = 2 * time.Second

// ErrAllUpstreamsFailed is returned when every configured upstream rejects or times out.
var ErrAllUpstreamsFailed = errors.New("all upstream DNS servers failed")

// Forwarder sends recursive queries to configured upstream resolvers with sequential fallback.
type Forwarder struct {
	upstreams []string
	client    *mdns.Client
	stats     *telemetry.Stats
}

// NewForwarderFromConfig builds an upstream forwarder from application configuration.
func NewForwarderFromConfig(cfg config.Config, stats *telemetry.Stats) (*Forwarder, error) {
	addrs, err := cfg.NormalizedUpstreams()
	if err != nil {
		return nil, err
	}
	return NewForwarder(addrs, stats), nil
}

func NewForwarder(upstreams []string, stats *telemetry.Stats) *Forwarder {
	addrs := make([]string, len(upstreams))
	copy(addrs, upstreams)

	return &Forwarder{
		upstreams: addrs,
		client: &mdns.Client{
			Net:     "udp",
			Timeout: defaultUpstreamTimeout,
		},
		stats: stats,
	}
}

// ParseUpstreams splits a comma-separated upstream list and normalizes each entry to host:port.
func ParseUpstreams(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	return NormalizeUpstreams(parts)
}

// NormalizeUpstreams normalizes each upstream entry to host:port form.
func NormalizeUpstreams(addrs []string) ([]string, error) {
	out := make([]string, 0, len(addrs))

	for _, part := range addrs {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		host, port, err := net.SplitHostPort(part)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				part = net.JoinHostPort(part, "53")
			} else {
				return nil, fmt.Errorf("invalid upstream %q: %w", part, err)
			}
		} else if host == "" || port == "" {
			return nil, fmt.Errorf("invalid upstream address %q", part)
		}

		out = append(out, part)
	}

	if len(out) == 0 {
		return nil, errors.New("at least one upstream DNS server is required")
	}

	return out, nil
}

// Exchange forwards req to upstream resolvers sequentially until one responds successfully.
func (f *Forwarder) Exchange(req *mdns.Msg) (*mdns.Msg, error) {
	if f == nil || len(f.upstreams) == 0 {
		return nil, ErrAllUpstreamsFailed
	}

	for _, upstream := range f.upstreams {
		resp, _, err := f.client.Exchange(req, upstream)
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}

		if f.stats != nil {
			f.stats.IncForwardedQuery()
		}
		return resp, nil
	}

	if f.stats != nil {
		f.stats.IncUpstreamFailure()
	}
	return nil, ErrAllUpstreamsFailed
}
