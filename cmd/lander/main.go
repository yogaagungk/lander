// Command lander is the ORBIT VPS daemon. It manages Nginx sites and exposes
// a local REST API authenticated with a bearer token.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/handler"
	"github.com/yogaagungk/lander/internal/service"
)

// version is injected at build time with -X main.version=...
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("lander exited", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	nginx := service.NewNginx(cfg, nil)

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", handler.Healthz(version, nginx.NginxActive))
	// TODO(L3): authenticated routes, bearer middleware, rate limiting.

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("lander listening", "addr", cfg.ListenAddr, "version", version)
		serverErr <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}
