package network

import "runtime"

// Config holds listener settings shared by UDP and TCP servers.
type Config struct {
	// Address is the listen address in host:port form (for example "[::]:53").
	Address string

	// ReusePortSockets is the number of SO_REUSEPORT sockets per protocol.
	// When zero or negative, runtime.NumCPU() is used.
	ReusePortSockets int
}

func (c Config) socketCount() int {
	n := c.ReusePortSockets
	if n <= 0 {
		n = runtime.NumCPU()
	}
	if n < 1 {
		n = 1
	}
	return n
}
