package network

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const shutdownTimeout = 10 * time.Second

type reactor struct {
	gnet.BuiltinEventEngine
	ctx    context.Context
	logger *slog.Logger
	cfg    Config
	proto  string
	engine gnet.Engine
}

func (r *reactor) gnetOptions() []gnet.Option {
	return []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
		gnet.WithReuseAddr(true),
		gnet.WithNumEventLoop(r.cfg.socketCount()),
	}
}

func (r *reactor) OnBoot(eng gnet.Engine) gnet.Action {
	r.engine = eng
	go func() {
		<-r.ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := r.engine.Stop(stopCtx); err != nil {
			r.logger.Warn("reactor shutdown failed", "protocol", r.proto, "error", err)
		}
	}()
	r.logger.Info("reactor started", "protocol", r.proto, "address", r.cfg.Address)
	return gnet.None
}

func runReactor(ctx context.Context, cfg Config, proto string, handler gnet.EventHandler, logger *slog.Logger, opts ...gnet.Option) error {
	if logger == nil {
		logger = slog.Default()
	}

	addr := gnetAddresses(proto, cfg.Address)
	done := make(chan error, 1)
	go func() {
		done <- gnet.Rotate(handler, addr, opts...)
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s reactor: %w", proto, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	case <-ctx.Done():
		err := <-done
		if err != nil {
			return fmt.Errorf("%s reactor: %w", proto, err)
		}
		return ctx.Err()
	}
}
