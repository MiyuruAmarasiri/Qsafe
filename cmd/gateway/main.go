package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/example/qsafe/internal/platform/logging"
)

func main() {
	var (
		addr        = flag.String("addr", ":8443", "HTTP listen address")
		mode        = flag.String("mode", "strict", "PQ mode (strict|hybrid)")
		aead        = flag.String("aead", "xchacha20poly1305", "AEAD suite")
		rotationSec = flag.Uint("rotation", 300, "Session rotation interval in seconds")
	)
	flag.Parse()

	logger, cleanup, err := logging.Global(logging.Config{
		ServiceName: "gateway",
		Environment: "dev",
		Level:       "info",
	})
	if err != nil {
		log.Fatalf("logger init: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = cleanup(ctx)
	}()

	srv, err := NewGatewayServer(GatewayConfig{
		Address:  *addr,
		Mode:     *mode,
		AEAD:     *aead,
		Rotation: time.Duration(*rotationSec) * time.Second,
		Logger:   logger,
	})
	if err != nil {
		logger.Fatal("init gateway", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	logger.Info("gateway listening", zap.String("addr", *addr))

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", zap.Error(err))
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", zap.Error(err))
	}
	logger.Info("gateway stopped")
}
