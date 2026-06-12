package network

import (
	"net"
	"net/netip"
)

// ClientIPFromAddr extracts a netip.Addr from a connection remote address.
func ClientIPFromAddr(remote net.Addr) netip.Addr {
	if remote == nil {
		return netip.Addr{}
	}

	switch addr := remote.(type) {
	case *net.UDPAddr:
		return ipToNetip(addr.IP)
	case *net.TCPAddr:
		return ipToNetip(addr.IP)
	default:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			return netip.Addr{}
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}
		}
		return ip.Unmap()
	}
}

func ipToNetip(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}
