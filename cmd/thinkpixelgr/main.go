package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	httpapi "github.com/thinkpixelgr/thinkpixelgr/internal/api/http"
	"github.com/thinkpixelgr/thinkpixelgr/internal/auth"
	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/observability"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("THINKPIXELGR_LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	configPath := flag.String("config", envOr("THINKPIXELGR_CONFIG", "./configs/config.yaml"), "configuration file")
	address := flag.String("listen", envOr("THINKPIXELGR_LISTEN", ":8080"), "HTTP listen address")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	var access auth.Controller = auth.Disabled{}
	if cfg.Auth.Enabled {
		access, err = auth.NewStaticBearer(cfg.Auth, os.LookupEnv)
		if err != nil {
			slog.Error("authentication configuration failed", "error", err)
			os.Exit(1)
		}
	}

	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		slog.Error("policy compilation failed", "error", err)
		os.Exit(1)
	}

	observer := observability.New(logger)
	handler := httpapi.New(engine.New(resolver, observer), resolver, access, observer)
	server := &http.Server{
		Addr:              *address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	slog.Info("ThinkPixelGR listening", "address", *address, "config", *configPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
