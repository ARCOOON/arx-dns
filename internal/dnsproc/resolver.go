package dnsproc

import (
	"net/netip"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

// defaultClientUDPSize is the receive buffer for upstream UDP exchanges (RFC 6891).
// 1232 bytes avoids fragmentation on typical 1500-byte MTU paths (1280 IPv6 minimum + headers).
const defaultClientUDPSize = 1232

// ExchangeResolver performs recursive DNS resolution for client queries.
type ExchangeResolver interface {
	Exchange(req *mdns.Msg, client netip.Addr) (*mdns.Msg, error)
	ECSCacheContext(client netip.Addr) storage.ECSContext
}
