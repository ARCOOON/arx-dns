package dnsproc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const defaultUpstreamTimeout = 2 * time.Second

// ErrAllUpstreamsFailed is returned when every configured upstream rejects or times out.
var ErrAllUpstreamsFailed = errors.New("all upstream DNS servers failed")

// Forwarder sends recursive queries to configured upstream resolvers with sequential fallback.
type Forwarder struct {
	upstreams        []string
	client           *mdns.Client
	stats            *telemetry.Stats
	dnssecValidation bool
	ecsEnabled       bool
	ecsIPv4PrefixLen uint8
	ecsIPv6PrefixLen uint8
}

// NewForwarderFromConfig builds an upstream forwarder from application configuration.
func NewForwarderFromConfig(cfg config.Config, stats *telemetry.Stats) (*Forwarder, error) {
	addrs, err := cfg.NormalizedUpstreams()
	if err != nil {
		return nil, err
	}
	f := NewForwarder(addrs, stats)
	f.dnssecValidation = cfg.Security.DNSSECValidation
	f.ecsEnabled = cfg.ECS.Enabled
	f.ecsIPv4PrefixLen = uint8(cfg.ECS.IPv4PrefixLength)
	f.ecsIPv6PrefixLen = uint8(cfg.ECS.IPv6PrefixLength)
	return f, nil
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

// ECSCacheContext returns ECS settings for response cache key generation.
func (f *Forwarder) ECSCacheContext(client netip.Addr) storage.ECSContext {
	if f == nil {
		return storage.ECSContext{}
	}
	return storage.ECSContext{
		Enabled:       f.ecsEnabled,
		Client:        client,
		IPv4PrefixLen: f.ecsIPv4PrefixLen,
		IPv6PrefixLen: f.ecsIPv6PrefixLen,
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
func (f *Forwarder) Exchange(req *mdns.Msg, client netip.Addr) (*mdns.Msg, error) {
	if f == nil || len(f.upstreams) == 0 {
		return nil, ErrAllUpstreamsFailed
	}

	upstreamReq, ecsForwarded := f.prepareUpstreamRequest(req, client)

	for _, upstream := range f.upstreams {
		resp, _, err := f.client.Exchange(upstreamReq, upstream)
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}

		if f.stats != nil {
			f.stats.IncForwardedQuery()
			if ecsForwarded {
				f.stats.IncECSQueriesForwarded()
			}
		}
		return resp, nil
	}

	if f.stats != nil {
		f.stats.IncUpstreamFailure()
	}
	return nil, ErrAllUpstreamsFailed
}

// prepareUpstreamRequest clones req, applies DNSSEC DO when enabled, and attaches ECS when configured.
func (f *Forwarder) prepareUpstreamRequest(req *mdns.Msg, client netip.Addr) (*mdns.Msg, bool) {
	upstreamReq := req.Copy()

	if _, hasECS := storage.ExtractECSSubnet(req); hasECS {
		if f != nil && f.dnssecValidation {
			f.applyDNSSECDO(upstreamReq, req)
		}
		return upstreamReq, true
	}

	ecsForwarded := false
	if f != nil && f.ecsEnabled && client.IsValid() {
		subnet := storage.BuildECSSubnet(client, f.ecsIPv4PrefixLen, f.ecsIPv6PrefixLen)
		if subnet != nil {
			f.ensureEDNS(upstreamReq, req)
			opt := upstreamReq.IsEdns0()
			opt.Option = append(opt.Option, subnet)
			ecsForwarded = true
		}
	}

	if f != nil && f.dnssecValidation {
		f.applyDNSSECDO(upstreamReq, req)
	}

	return upstreamReq, ecsForwarded
}

func (f *Forwarder) ensureEDNS(upstreamReq, req *mdns.Msg) {
	if upstreamReq.IsEdns0() != nil {
		return
	}
	udpSize := uint16(mdns.DefaultMsgSize)
	if opt := req.IsEdns0(); opt != nil && opt.UDPSize() >= mdns.MinMsgSize {
		udpSize = opt.UDPSize()
	}
	upstreamReq.SetEdns0(udpSize, false)
}

func (f *Forwarder) applyDNSSECDO(upstreamReq, req *mdns.Msg) {
	if opt := upstreamReq.IsEdns0(); opt != nil {
		if opt.UDPSize() < mdns.MinMsgSize {
			opt.SetUDPSize(mdns.MinMsgSize)
		}
		opt.SetDo()
		return
	}

	udpSize := uint16(mdns.DefaultMsgSize)
	if opt := req.IsEdns0(); opt != nil && opt.UDPSize() >= mdns.MinMsgSize {
		udpSize = opt.UDPSize()
	}
	upstreamReq.SetEdns0(udpSize, true)
}

// SetDNSSECValidation enables or disables the EDNS DO bit on upstream requests.
func (f *Forwarder) SetDNSSECValidation(enabled bool) {
	if f != nil {
		f.dnssecValidation = enabled
	}
}

// SetECS enables EDNS Client Subnet forwarding with the given prefix lengths.
func (f *Forwarder) SetECS(enabled bool, ipv4PrefixLen, ipv6PrefixLen uint8) {
	if f == nil {
		return
	}
	f.ecsEnabled = enabled
	f.ecsIPv4PrefixLen = ipv4PrefixLen
	f.ecsIPv6PrefixLen = ipv6PrefixLen
}

// PrepareUpstreamRequest returns the upstream query with EDNS options applied.
func (f *Forwarder) PrepareUpstreamRequest(req *mdns.Msg, client netip.Addr) *mdns.Msg {
	if f == nil {
		return req.Copy()
	}
	prepared, _ := f.prepareUpstreamRequest(req, client)
	return prepared
}
