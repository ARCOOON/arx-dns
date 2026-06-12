package network

import (
	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func recordAnswer(stats *telemetry.Stats, response []byte) {
	msg := new(mdns.Msg)
	if err := msg.Unpack(response); err != nil {
		return
	}
	switch msg.Rcode {
	case mdns.RcodeNameError:
		stats.IncNXDomainAnswer()
	case mdns.RcodeRefused:
		stats.IncRefusedAnswer()
	case mdns.RcodeSuccess:
		if msg.Authoritative {
			stats.IncAuthoritativeAnswer()
		}
	}
}
