package storage

import (
	"fmt"
	"net"
	"net/netip"

	mdns "github.com/miekg/dns"
)

// ECSContext carries EDNS Client Subnet settings used for cache key synthesis.
type ECSContext struct {
	Enabled       bool
	Client        netip.Addr
	IPv4PrefixLen uint8
	IPv6PrefixLen uint8
}

// ExtractECSSubnet returns the first EDNS0 Client Subnet option from req.
func ExtractECSSubnet(req *mdns.Msg) (*mdns.EDNS0_SUBNET, bool) {
	if req == nil {
		return nil, false
	}
	opt := req.IsEdns0()
	if opt == nil {
		return nil, false
	}
	for _, option := range opt.Option {
		subnet, ok := option.(*mdns.EDNS0_SUBNET)
		if ok {
			return subnet, true
		}
	}
	return nil, false
}

// ECSCacheSuffix returns a deterministic ECS scope token for cache keys.
// When the query already carries ECS, that prefix is used. When ECS is enabled
// and the query lacks ECS, the suffix is synthesized from the client address.
func ECSCacheSuffix(req *mdns.Msg, ecs ECSContext) string {
	if subnet, ok := ExtractECSSubnet(req); ok {
		return formatECSSuffix(subnet.Family, subnet.Address, subnet.SourceNetmask)
	}
	if !ecs.Enabled || !ecs.Client.IsValid() {
		return ""
	}
	subnet := BuildECSSubnet(ecs.Client, ecs.IPv4PrefixLen, ecs.IPv6PrefixLen)
	if subnet == nil {
		return ""
	}
	return formatECSSuffix(subnet.Family, subnet.Address, subnet.SourceNetmask)
}

// BuildECSSubnet constructs an RFC 7871 Client Subnet option from client.
func BuildECSSubnet(client netip.Addr, ipv4PrefixLen, ipv6PrefixLen uint8) *mdns.EDNS0_SUBNET {
	if !client.IsValid() {
		return nil
	}
	client = client.Unmap()

	if client.Is4() {
		prefixLen := clampPrefixLen(ipv4PrefixLen, 32)
		ip := maskedIPv4(client, prefixLen)
		return &mdns.EDNS0_SUBNET{
			Code:          mdns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: prefixLen,
			SourceScope:   0,
			Address:       ip,
		}
	}

	if client.Is6() {
		prefixLen := clampPrefixLen(ipv6PrefixLen, 128)
		ip := maskedIPv6(client, prefixLen)
		return &mdns.EDNS0_SUBNET{
			Code:          mdns.EDNS0SUBNET,
			Family:        2,
			SourceNetmask: prefixLen,
			SourceScope:   0,
			Address:       ip,
		}
	}

	return nil
}

func formatECSSuffix(family uint16, address net.IP, prefixLen uint8) string {
	if address == nil {
		return fmt.Sprintf("%d|/%d", family, prefixLen)
	}
	if family == 1 {
		ip4 := address.To4()
		if ip4 == nil {
			ip4 = address
		}
		return fmt.Sprintf("1|%s|%d", ip4.String(), prefixLen)
	}
	return fmt.Sprintf("2|%s|%d", address.String(), prefixLen)
}

func clampPrefixLen(prefixLen, max uint8) uint8 {
	if prefixLen > max {
		return max
	}
	return prefixLen
}

func maskedIPv4(client netip.Addr, prefixLen uint8) net.IP {
	masked := netip.PrefixFrom(client, int(prefixLen)).Masked().Addr()
	out := masked.As4()
	return net.IPv4(out[0], out[1], out[2], out[3])
}

func maskedIPv6(client netip.Addr, prefixLen uint8) net.IP {
	prefix := netip.PrefixFrom(client, int(prefixLen)).Masked()
	b := prefix.Addr().As16()
	return net.IP(b[:])
}
