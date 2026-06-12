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

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

func main() {
	listen := flag.String("listen", "0.0.0.0", "IP address to bind to")
	port := flag.Int("port", 53, "port to bind to")
	loops := flag.Int("loops", 0, "number of gnet event loops (0 uses all CPU cores)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := storage.NewMemory()
	seedDemoZone(store)

	proc := dnsproc.New(store)
	stats := telemetry.New()

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

func seedDemoZone(store *storage.Memory) {
	store.InsertRR(&mdns.A{
		Hdr: mdns.RR_Header{
			Name:   "router.arx.local.",
			Rrtype: mdns.TypeA,
			Class:  mdns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("10.10.0.1"),
	})

	store.InsertRR(&mdns.AAAA{
		Hdr: mdns.RR_Header{
			Name:   "router.arx.local.",
			Rrtype: mdns.TypeAAAA,
			Class:  mdns.ClassINET,
			Ttl:    300,
		},
		AAAA: net.ParseIP("fd00::1"),
	})

	store.InsertRR(&mdns.CNAME{
		Hdr: mdns.RR_Header{
			Name:   "www.arx.local.",
			Rrtype: mdns.TypeCNAME,
			Class:  mdns.ClassINET,
			Ttl:    300,
		},
		Target: "router.arx.local.",
	})
}
