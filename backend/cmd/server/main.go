// Command server runs the secrets API.
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

	"github.com/ruslanrwx/secrets/backend/internal/api"
	"github.com/ruslanrwx/secrets/backend/internal/config"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// version is stamped at build time with -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	log.Info("starting secrets api", "version", version, "port", cfg.Port)

	keys, err := cryptoutil.NewKeyring(cfg.MasterKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer st.Close()

	if cfg.MigrateOnBoot {
		if err := st.Migrate(ctx); err != nil {
			return err
		}
	}

	// Refuse to serve with a master key that cannot open existing data, rather
	// than failing later on a per-secret basis.
	settings, err := st.Settings(ctx)
	if err != nil {
		return err
	}
	if settings.Initialized {
		if err := keys.VerifyKeyCheck(settings.KeyCheck); err != nil {
			return err
		}
		log.Info("master key verified", "keyId", keys.KeyID())
	} else {
		log.Info("installation is not set up yet; open the web UI to create the first administrator")
	}

	server := api.New(cfg, st, keys, log, version)

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.Routes(cfg.CORSOrigins),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return httpServer.Shutdown(shutdownCtx)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
