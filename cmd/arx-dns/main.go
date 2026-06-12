package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func main() {
	listen := flag.String("listen", "0.0.0.0", "IP address to bind to")
	port := flag.Int("port", 53, "port to bind to")
	loops := flag.Int("loops", 0, "number of gnet event loops (0 uses all CPU cores)")
	zones := flag.String("zones", "./zones", "directory containing BIND .zone files")
	upstreams := flag.String("upstreams", "1.1.1.1:53,1.0.0.1:53", "comma-separated upstream DNS resolvers for recursive forwarding")
	trustedSubnets := flag.String("trusted-subnets", "127.0.0.0/8,10.0.0.0/8,192.168.0.0/16", "comma-separated CIDR prefixes allowed to use recursive forwarding")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := storage.NewMemory()
	storage.LoadZonesFromDir(*zones, store, logger)

	if err := storage.StartWatcher(ctx, *zones, store, logger); err != nil {
		logger.Error("failed to start zone file watcher", "directory", *zones, "error", err)
		os.Exit(1)
	}

	stats := telemetry.New()

	acl, err := network.ParseACL(*trustedSubnets)
	if err != nil {
		logger.Error("invalid trusted subnets configuration", "trusted_subnets", *trustedSubnets, "error", err)
		os.Exit(1)
	}

	upstreamAddrs, err := dnsproc.ParseUpstreams(*upstreams)
	if err != nil {
		logger.Error("invalid upstream configuration", "upstreams", *upstreams, "error", err)
		os.Exit(1)
	}

	responseCache, err := storage.NewResponseCache()
	if err != nil {
		logger.Error("failed to initialize response cache", "error", err)
		os.Exit(1)
	}

	forwarder := dnsproc.NewForwarder(upstreamAddrs, stats)
	proc := dnsproc.New(store, forwarder, responseCache, stats, acl)

	cfg := network.Config{
		Address:          net.JoinHostPort(*listen, strconv.Itoa(*port)),
		ReusePortSockets: *loops,
	}

	udpReactor := network.NewUDPReactor(cfg, logger, stats, proc)
	tcpReactor := network.NewTCPReactor(cfg, logger, stats, proc)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	startReactor := func(name string, run func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("reactor stopped with error", "protocol", name, "error", err)
				errCh <- err
				stop()
			}
		}()
	}

	logger.Info("starting arx-dns reactors",
		"address", cfg.Address,
		"event_loops", cfg.ReusePortSockets,
		"upstreams", upstreamAddrs,
		"trusted_subnets", *trustedSubnets,
	)
	startReactor("udp", udpReactor.Run)
	startReactor("tcp", tcpReactor.Run)

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("fatal reactor error", "error", err)
		os.Exit(1)
	}

	stop()
	wg.Wait()
	logger.Info("arx-dns stopped", "stats", stats.Snapshot())
}
