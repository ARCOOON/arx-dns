package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const defaultListenAddress = "[::]:53"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := network.Config{
		Address: defaultListenAddress,
	}
	stats := telemetry.New()

	udpReactor := network.NewUDPReactor(cfg, logger, stats)
	tcpReactor := network.NewTCPReactor(cfg, logger, stats)

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

	logger.Info("starting arx-dns reactors", "address", cfg.Address)
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
