package network

import (
	"log/slog"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

// Reactors holds UDP and TCP DNS reactors created from application configuration.
type Reactors struct {
	UDP *UDPReactor
	TCP *TCPReactor
}

// NewReactors creates UDP and TCP reactors using listener settings from cfg.
func NewReactors(cfg config.Config, logger *slog.Logger, stats *telemetry.Stats, proc *dnsproc.Processor) Reactors {
	listener := Config{
		Address:          cfg.ListenAddress(),
		ReusePortSockets: cfg.Server.EventLoops,
	}
	return Reactors{
		UDP: NewUDPReactor(listener, logger, stats, proc),
		TCP: NewTCPReactor(listener, logger, stats, proc),
	}
}
