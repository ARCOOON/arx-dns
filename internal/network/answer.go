package network

import (
	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func recordAnswer(stats *telemetry.Stats, response []byte) {
	rcode, err := dnsproc.RcodeFromPayload(response)
	if err != nil {
		return
	}
	switch rcode {
	case mdns.RcodeNameError:
		stats.IncNXDomainAnswer()
	default:
		stats.IncAuthoritativeAnswer()
	}
}
