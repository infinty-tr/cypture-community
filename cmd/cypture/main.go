package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"cypture/internal/auth"
	"cypture/internal/config"
	"cypture/internal/db"
	"cypture/internal/server"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := config.Load()

	for _, a := range os.Args[1:] {
		if a == "-check-config" || a == "--check-config" {
			if err := cfg.Validate(); err != nil {
				slog.Error("config check FAILED: " + err.Error())
				os.Exit(1)
			}
			slog.Info("config check OK", "env", cfg.Env)
			os.Exit(0)
		}
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("refusing to start: "+err.Error(), "env", cfg.Env)
		os.Exit(1)
	}

	gdb, err := db.Open(cfg.DBPath, cfg.Dev())
	if err != nil {
		slog.Error("database init failed", "err", err)
		os.Exit(1)
	}

	if err := auth.EnsureAdmin(gdb, cfg); err != nil {
		slog.Error("seed admin failed", "err", err)
		os.Exit(1)
	}

	srv := server.New(cfg, gdb)
	srv.Scans.Recover()

	addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("cypture listening",
			"addr", "http://"+addr,
			"admin", "http://"+addr+"/admin",
			"env", cfg.Env,
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	slog.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("bye")
}
