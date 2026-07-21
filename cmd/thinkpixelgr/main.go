package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	httpapi "github.com/thinkpixelgr/thinkpixelgr/internal/api/http"
	"github.com/thinkpixelgr/thinkpixelgr/internal/config"
	"github.com/thinkpixelgr/thinkpixelgr/internal/engine"
	"github.com/thinkpixelgr/thinkpixelgr/internal/policy"
)

func main() {
	configPath := flag.String("config", envOr("THINKPIXELGR_CONFIG", "./configs/config.yaml"), "configuration file")
	address := flag.String("listen", envOr("THINKPIXELGR_LISTEN", ":8080"), "HTTP listen address")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	resolver, err := policy.NewResolver(cfg)
	if err != nil {
		slog.Error("policy compilation failed", "error", err)
		os.Exit(1)
	}

	handler := httpapi.New(engine.New(resolver), resolver)
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
