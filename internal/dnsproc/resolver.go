package dnsproc

import (
	"net/netip"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

// ExchangeResolver performs recursive DNS resolution for client queries.
type ExchangeResolver interface {
	Exchange(req *mdns.Msg, client netip.Addr) (*mdns.Msg, error)
	ECSCacheContext(client netip.Addr) storage.ECSContext
}
