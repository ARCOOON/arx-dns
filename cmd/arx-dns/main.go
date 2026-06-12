package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/firewall"
	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func main() {
	configPath := flag.String("config", "./config.toml", "path to the TOML configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load configuration", "config", *configPath, "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := storage.NewMemory()
	storage.LoadZones(cfg.Zones, store, logger)

	if err := storage.StartWatcher(ctx, cfg.Zones, store, logger); err != nil {
		logger.Error("failed to start zone file watcher", "directory", cfg.Zones.Directory, "error", err)
		os.Exit(1)
	}

	fwAction, err := firewall.ParseBlockAction(cfg.Firewall.BlockAction)
	if err != nil {
		logger.Error("invalid firewall block action", "block_action", cfg.Firewall.BlockAction, "error", err)
		os.Exit(1)
	}

	fw := firewall.New(fwAction)
	firewall.Load(cfg.Firewall, fw, logger)

	if err := firewall.StartWatcher(ctx, cfg.Firewall, fw, logger); err != nil {
		logger.Error("failed to start blocklist watcher", "directory", cfg.Firewall.BlocklistsDirectory, "error", err)
		os.Exit(1)
	}

	stats := telemetry.New()

	responseCache, err := storage.NewResponseCache()
	if err != nil {
		logger.Error("failed to initialize response cache", "error", err)
		os.Exit(1)
	}

	acl, err := network.ACLFromConfig(cfg)
	if err != nil {
		logger.Error("invalid trusted subnets configuration", "trusted_subnets", cfg.Recursive.TrustedSubnets, "error", err)
		os.Exit(1)
	}

	forwarder, err := dnsproc.NewForwarderFromConfig(cfg, stats)
	if err != nil {
		logger.Error("invalid upstream configuration", "upstreams", cfg.Recursive.Upstreams, "error", err)
		os.Exit(1)
	}

	proc := dnsproc.New(store, forwarder, responseCache, stats, acl, fw)
	reactors := network.NewReactors(cfg, logger, stats, proc)

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	startService := func(name string, run func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("service stopped with error", "protocol", name, "error", err)
				errCh <- err
				stop()
			}
		}()
	}

	logger.Info("starting arx-dns",
		"config", *configPath,
		"address", cfg.ListenAddress(),
		"event_loops", cfg.Server.EventLoops,
		"zones", cfg.Zones.Directory,
		"upstreams", cfg.Recursive.Upstreams,
		"trusted_subnets", cfg.Recursive.TrustedSubnets,
		"blocklists", cfg.Firewall.BlocklistsDirectory,
		"block_action", fwAction,
		"encrypted_dns", cfg.EncryptedDNSEnabled(),
	)
	startService("udp", reactors.UDP.Run)
	startService("tcp", reactors.TCP.Run)

	if cfg.EncryptedDNSEnabled() {
		tlsCfg, err := cfg.BuildTLSConfig()
		if err != nil {
			logger.Error("failed to load tls configuration", "error", err)
			os.Exit(1)
		}

		if strings.TrimSpace(cfg.Listeners.DoT) != "" {
			dot := network.NewDoTServer(cfg.Listeners.DoT, tlsCfg, logger, stats, proc)
			startService("dot", dot.Run)
		}
		if strings.TrimSpace(cfg.Listeners.DoH) != "" {
			doh := network.NewDoHServer(cfg.Listeners.DoH, tlsCfg, logger, stats, proc)
			startService("doh", doh.Run)
		}
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("fatal service error", "error", err)
		os.Exit(1)
	}

	stop()
	wg.Wait()
	logger.Info("arx-dns stopped", "stats", stats.Snapshot())
}
