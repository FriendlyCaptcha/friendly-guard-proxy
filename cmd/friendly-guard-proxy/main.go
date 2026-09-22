package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/friendlycaptcha/friendly-guard-proxy/internal/config"
	guardpkg "github.com/friendlycaptcha/friendly-guard-proxy/internal/guard"
)

const (
	serverReadHeaderTimeout = 10 * time.Second
	serverIdleTimeout       = 120 * time.Second
	serverShutdownTimeout   = 10 * time.Second
)

func main() {
	configPath := flag.String("config", "friendly-guard-proxy.yml", "Path to the Friendly Guard Proxy YAML configuration")
	logLevelName := flag.String("log-level", "info", "Log level: debug, info, warn, or error")
	flag.Parse()

	logLevel, err := parseLogLevel(*logLevelName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	guard, err := guardpkg.NewProxy(cfg)
	if err != nil {
		logger.Error("failed to initialize Friendly Guard Proxy", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           guard,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("Friendly Guard Proxy listening", "listen", cfg.Server.Listen, "upstream", cfg.Upstream.Origin)
		errCh <- server.ListenAndServe()
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stopCh:
		logger.Info("Friendly Guard Proxy shutting down", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Friendly Guard Proxy stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	if err := server.Shutdown(ctx); err != nil {
		cancel()
		logger.Error("Friendly Guard Proxy graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	cancel()
}

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: expected debug, info, warn, or error", level)
	}
}
