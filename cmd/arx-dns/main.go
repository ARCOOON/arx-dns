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

	"github.com/ARCOOON/arx-dns/internal/api"
	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/firewall"
	"github.com/ARCOOON/arx-dns/internal/logger"
	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/runtime"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func main() {
	configPath := flag.String("config", "./config.toml", "path to the TOML configuration file")
	flag.Parse()

	// Step 0: Bootstrap runtime directories and default configuration file.
	if err := config.Bootstrap(*configPath); err != nil {
		slog.Default().Error("failed to bootstrap runtime environment", "config", *configPath, "error", err)
		os.Exit(1)
	}

	// Step 1: Load configuration.
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Default().Error("failed to load configuration", "config", *configPath, "error", err)
		os.Exit(1)
	}

	telemetryDB, err := telemetry.OpenDB("./data")
	if err != nil {
		slog.Default().Error("failed to open telemetry databases", "error", err)
		os.Exit(1)
	}
	defer telemetryDB.Close()

	log, err := logger.New(cfg.Server.LogLevel, telemetryDB.Main())
	if err != nil {
		slog.Default().Error("invalid log level configuration", "log_level", cfg.Server.LogLevel, "error", err)
		os.Exit(1)
	}
	if err := logger.UpdateConfig(telemetryDB.Main(), logger.Config{
		Level: cfg.Server.LogLevel,
		Rotation: logger.RotationConfig{
			FilePath:   cfg.Logging.FilePath,
			MaxSizeMB:  cfg.Logging.MaxSizeMB,
			MaxBackups: cfg.Logging.MaxBackups,
			MaxAgeDays: cfg.Logging.MaxAgeDays,
		},
	}); err != nil {
		log.Warn("failed to sync logging config from config.toml", "error", err)
	}
	logger := log

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Step 2: Load zones and blocklists.
	store := storage.NewMemory()
	storage.LoadZones(cfg.Zones, store, logger)

	fwAction, err := firewall.ParseBlockAction(cfg.Firewall.BlockAction)
	if err != nil {
		logger.Error("invalid firewall block action", "block_action", cfg.Firewall.BlockAction, "error", err)
		os.Exit(1)
	}

	fw := firewall.New(fwAction)
	firewall.Load(cfg.Firewall, telemetryDB.Main(), fw, logger)

	// Step 3: Fetch/load root hints (falls back to built-in addresses on failure).
	rootHints := dnsproc.LoadRootHints(
		&cfg,
		cfg.Resolver.RootHintsFile,
		cfg.Resolver.AutoUpdateRootHints,
		config.DefaultRootHints(),
		logger,
	)
	if len(rootHints) == 0 {
		logger.Error("no root hints available after fetch and fallback", "file", cfg.Resolver.RootHintsFile)
		os.Exit(1)
	}

	// Step 4: Initialize response cache, telemetry workers, and shared runtime services.
	stats := telemetry.New()

	telemetry.StartWorkers(ctx, stats, telemetryDB, logger)

	responseCache, err := storage.NewResponseCache(logger)
	if err != nil {
		logger.Error("failed to initialize response cache", "error", err)
		os.Exit(1)
	}

	acl, err := network.ACLFromConfig(cfg)
	if err != nil {
		logger.Error("invalid trusted subnets configuration", "trusted_subnets", cfg.Recursive.TrustedSubnets, "error", err)
		os.Exit(1)
	}

	xfrACL, err := network.ACLFromXFRConfig(cfg)
	if err != nil {
		logger.Error("invalid zone transfer ACL configuration", "allowed_subnets", cfg.XFR.AllowedSubnets, "error", err)
		os.Exit(1)
	}

	notifySlaves, err := cfg.NormalizedNotifySlaves()
	if err != nil {
		logger.Error("invalid notify slaves configuration", "notify_slaves", cfg.XFR.NotifySlaves, "error", err)
		os.Exit(1)
	}
	notifier := dnsproc.NewNotifier(cfg.XFR.Enabled, notifySlaves, cfg.ListenAddress(), stats, logger)

	// Step 5: Initialize resolver and pre-warm upstream connections.
	var forwarder *dnsproc.Forwarder
	var iterative *dnsproc.IterativeResolver

	switch cfg.ResolverMode() {
	case "forward":
		forwarder, err = dnsproc.NewForwarderFromConfig(cfg, stats, logger)
		if err != nil {
			logger.Error("invalid upstream configuration", "upstreams", cfg.Recursive.Upstreams, "error", err)
			os.Exit(1)
		}
		if err := forwarder.PreWarm(); err != nil {
			logger.Error("upstream pre-warm failed", "upstreams", cfg.Recursive.Upstreams, "error", err)
			os.Exit(1)
		}
	case "iterative":
		iterative, err = dnsproc.NewIterativeFromConfig(cfg, rootHints, stats, logger)
		if err != nil {
			logger.Error("invalid iterative resolver configuration", "root_hints", rootHints, "error", err)
			os.Exit(1)
		}
	default:
		logger.Error("invalid resolver mode", "resolver_mode", cfg.ResolverMode())
		os.Exit(1)
	}

	var cookieEngine *network.CookieEngine
	if cfg.Security.DNSCookiesEnabled {
		secret, err := cfg.DNSCookieSecretBytes()
		if err != nil {
			logger.Error("invalid dns cookie secret", "error", err)
			os.Exit(1)
		}
		cookieEngine = network.NewCookieEngine(secret)
	}

	queryACL, err := dnsproc.NewQueryAccessChecker(telemetryDB.Main())
	if err != nil {
		logger.Error("failed to load query access ACL", "error", err)
		os.Exit(1)
	}

	proc := dnsproc.New(store, forwarder, iterative, cfg.ResolverMode(), responseCache, stats, acl, queryACL, fw, cfg.Security.DNSSECValidation, cookieEngine, cfg.NormalizedTSIGKeys(), cfg.Zones.Directory, cfg.XFR.Enabled, xfrACL, notifier, logger)

	if err := firewall.StartWatcher(ctx, cfg.Firewall, telemetryDB.Main(), fw, logger); err != nil {
		logger.Error("failed to start blocklist watcher", "directory", cfg.Firewall.BlocklistsDirectory, "error", err)
		os.Exit(1)
	}

	if err := storage.StartWatcher(ctx, cfg.Zones, store, logger, func() {
		notifier.NotifyZones(dnsproc.ZoneOrigins(store.ListZones()))
	}); err != nil {
		logger.Error("failed to start zone file watcher", "directory", cfg.Zones.Directory, "error", err)
		os.Exit(1)
	}

	rrl := network.NewRateLimiter(cfg.RateLimit, stats)
	defer rrl.Close()

	// Step 6: Start listeners (reactors bind to port 53 only after steps 1-5 succeed).
	reactors := network.NewReactors(cfg, logger, stats, proc, rrl)

	var wg sync.WaitGroup
	errCh := make(chan error, 5)

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
		"log_level", cfg.Server.LogLevel,
		"address", cfg.ListenAddress(),
		"api", cfg.API.Listen,
		"event_loops", cfg.Server.EventLoops,
		"zones", cfg.Zones.Directory,
		"upstreams", cfg.Recursive.Upstreams,
		"resolver_mode", cfg.ResolverMode(),
		"root_hints_file", cfg.Resolver.RootHintsFile,
		"auto_update_root_hints", cfg.Resolver.AutoUpdateRootHints,
		"root_hints_count", len(rootHints),
		"trusted_subnets", cfg.Recursive.TrustedSubnets,
		"blocklists", cfg.Firewall.BlocklistsDirectory,
		"block_action", fwAction,
		"encrypted_dns", cfg.EncryptedDNSEnabled(),
		"dnssec_validation", cfg.Security.DNSSECValidation,
		"dns_cookies_enabled", cfg.Security.DNSCookiesEnabled,
		"rate_limit_enabled", cfg.RateLimit.Enabled,
		"rate_limit_rps", cfg.RateLimit.RequestsPerSecond,
		"rate_limit_burst", cfg.RateLimit.Burst,
		"dynamic_update_keys", len(cfg.Update.Keys),
		"xfr_enabled", cfg.XFR.Enabled,
		"xfr_allowed_subnets", cfg.XFR.AllowedSubnets,
		"notify_slaves", cfg.XFR.NotifySlaves,
	)
	runtimeApplier := &runtime.Applier{
		Processor:  proc,
		Forwarder:  forwarder,
		RateLimit:  rrl,
		TrustedACL: acl,
		XFRACL:     xfrACL,
		Firewall:   fw,
		Store:      store,
		Telemetry:  telemetryDB,
		Logger:     logger,
	}

	apiServer := api.New(cfg, *configPath, stats, telemetryDB, store, fw, queryACL, notifier, runtimeApplier, logger)
	startService("api", apiServer.Run)
	startService("udp", reactors.UDP.Run)
	startService("tcp", reactors.TCP.Run)

	if cfg.EncryptedDNSEnabled() {
		tlsCfg, err := cfg.BuildTLSConfig()
		if err != nil {
			logger.Error("failed to load tls configuration", "error", err)
			os.Exit(1)
		}

		if strings.TrimSpace(cfg.Listeners.DoT) != "" {
			dot := network.NewDoTServer(cfg.Listeners.DoT, tlsCfg, logger, stats, proc, rrl)
			startService("dot", dot.Run)
		}
		if strings.TrimSpace(cfg.Listeners.DoH) != "" {
			doh := network.NewDoHServer(cfg.Listeners.DoH, tlsCfg, logger, stats, proc, rrl)
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
