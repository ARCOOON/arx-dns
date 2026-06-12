package network

import (
	"fmt"
	"net"
	"strings"
)

func gnetAddresses(proto, address string) []string {
	if strings.Contains(address, "://") {
		return []string{address}
	}

	addrs := []string{fmt.Sprintf("%s://%s", proto, address)}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return addrs
	}

	if host == "::" || host == "[::]" {
		addrs = append(addrs, fmt.Sprintf("%s4://0.0.0.0:%s", proto, port))
	}

	return addrs
}
