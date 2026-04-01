package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nullbore/nullbore-server/internal/api"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/dash"
	"github.com/nullbore/nullbore-server/internal/store"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

func main() {
	port := flag.String("port", envOr("NULLBORE_PORT", "8443"), "Server listen port")
	host := flag.String("host", envOr("NULLBORE_HOST", "0.0.0.0"), "Bind address")
	tlsCert := flag.String("tls-cert", envOr("NULLBORE_TLS_CERT", ""), "TLS certificate path")
	tlsKey := flag.String("tls-key", envOr("NULLBORE_TLS_KEY", ""), "TLS key path")
	tlsDomain := flag.String("tls-domain", envOr("NULLBORE_TLS_DOMAIN", ""), "Domain(s) for auto Let's Encrypt (comma-separated)")
	tlsEmail := flag.String("tls-email", envOr("NULLBORE_TLS_EMAIL", ""), "Email for Let's Encrypt notifications")
	tlsCacheDir := flag.String("tls-cache", envOr("NULLBORE_TLS_CACHE", ""), "Cert cache directory (default: ~/.nullbore/certs)")
	apiKeys := flag.String("api-keys", envOr("NULLBORE_API_KEYS", ""), "Comma-separated API keys (dev mode)")
	baseDomain := flag.String("base-domain", envOr("NULLBORE_BASE_DOMAIN", ""), "Base domain for subdomain routing (e.g. tunnel.nullbore.com)")
	dbPath := flag.String("db", envOr("NULLBORE_DB", "nullbore.db"), "SQLite database path")
	eventsDBPath := flag.String("events-db", envOr("NULLBORE_EVENTS_DB", "events.db"), "SQLite events database path")
	dashPassword := flag.String("dash-password", envOr("NULLBORE_DASH_PASSWORD", ""), "Dashboard password (empty = dashboard disabled)")
	webhookTarget := flag.String("webhook-target", envOr("NULLBORE_WEBHOOK_TARGET", ""), "Dashboard URL for event dispatch (e.g. https://nullbore.com)")
	webhookSecret := flag.String("webhook-secret", envOr("NULLBORE_WEBHOOK_SECRET", ""), "Shared secret for internal event dispatch")
	adminSecret := flag.String("admin-secret", envOr("NULLBORE_ADMIN_SECRET", ""), "Shared secret for admin API (dashboard→server)")
	maxTunnels := flag.Int("max-tunnels", envOrInt("NULLBORE_MAX_TUNNELS", 10), "Max tunnels per client (0 = unlimited)")
	flag.Parse()

	// Set up structured logging
	logFormat := envOr("NULLBORE_LOG_FORMAT", "json")
	var logHandler slog.Handler
	if logFormat == "text" {
		logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		logHandler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	// Initialize stores
	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer db.Close()
	slog.Info("database ready", "path", *dbPath)

	events, err := store.NewEventStore(*eventsDBPath)
	if err != nil {
		log.Fatalf("events database error: %v", err)
	}
	defer events.Close()
	slog.Info("events database ready", "path", *eventsDBPath)

	// Initialize auth provider
	// If webhook target (dashboard URL) is configured, use remote auth
	// which validates keys against the dashboard DB. Static keys are
	// kept as a fallback for self-hosted/dev mode.
	var authProvider auth.Provider
	if *webhookTarget != "" && *webhookSecret != "" {
		remote := auth.NewRemoteProvider(*webhookTarget, *webhookSecret)
		remote.StartCacheReaper()
		slog.Info("auth: remote validation", "target", *webhookTarget)

		// Use a combo provider: try remote first, fall back to static
		authProvider = &auth.ComboProvider{
			Primary:  remote,
			Fallback: auth.NewStaticProvider(*apiKeys),
		}
	} else {
		authProvider = auth.NewStaticProvider(*apiKeys)
		slog.Info("auth: static keys")
	}

	// Initialize tunnel registry
	registry := tunnel.NewRegistry()
	if *maxTunnels > 0 {
		registry.SetLimits(tunnel.ConnectionLimit{MaxTunnels: *maxTunnels})
		slog.Info("connection limits", "max_tunnels", *maxTunnels)
	} else {
		registry.SetLimits(tunnel.ConnectionLimit{MaxTunnels: 0})
		slog.Info("connection limits", "max_tunnels", "unlimited")
	}

	// Restore active tunnels from DB (survive restarts)
	if db != nil {
		restored, err := db.LoadActiveTunnels()
		if err != nil {
			slog.Error("failed to load active tunnels", "error", err)
		} else if len(restored) > 0 {
			for _, rec := range restored {
				t := &tunnel.Tunnel{
					ID:        rec.ID,
					Slug:      rec.Slug,
					ClientID:  rec.ClientID,
					LocalPort: rec.LocalPort,
					Name:      rec.Name,
					TTL:       tunnel.Duration(time.Duration(rec.TTL) * time.Second),
					Mode:      "relay",
					CreatedAt: rec.CreatedAt,
					ExpiresAt: rec.ExpiresAt,
					BytesIn:   rec.BytesIn,
					BytesOut:  rec.BytesOut,
					Requests:  rec.Requests,
				}
				registry.Restore(t)
			}
			slog.Info("restored tunnels from database", "count", len(restored))
		}
	}

	// Periodic stats flush — save tunnel stats to DB every 30s
	if db != nil {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				tunnels := registry.List("")
				for _, t := range tunnels {
					db.FlushTunnelStats(t.ID, t.BytesIn, t.BytesOut, t.Requests, t.ExpiresAt)
				}
			}
		}()
	}

	// Register event handler for webhook dispatch
	if *webhookTarget != "" {
		target := *webhookTarget + "/internal/events"
		secret := *webhookSecret
		slog.Info("event dispatch configured", "target", target)
		registry.OnEvent(func(e tunnel.Event) {
			body, _ := json.Marshal(e)
			req, err := http.NewRequest("POST", target, bytes.NewReader(body))
			if err != nil {
				slog.Error("event dispatch failed", "error", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			if secret != "" {
				req.Header.Set("X-Internal-Secret", secret)
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				slog.Error("event dispatch failed", "error", err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				slog.Warn("event dispatch non-2xx", "target", target, "status", resp.StatusCode)
			}
		})
	}

	// Start TTL reaper
	go registry.StartReaper()

	// Prune old events and request logs every hour (keep 90 days for events, 7 days for request logs)
	if events != nil {
		go func() {
			for {
				time.Sleep(1 * time.Hour)
				events.PruneRequestLog(7 * 24 * time.Hour)
				events.PruneEvents(90 * 24 * time.Hour)
			}
		}()
	}

	// Build TLS config
	var domains []string
	if *tlsDomain != "" {
		for _, d := range strings.Split(*tlsDomain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}

	tlsCfg := &api.TLSConfig{
		CertFile:   *tlsCert,
		KeyFile:    *tlsKey,
		Domains:    domains,
		Email:      *tlsEmail,
		CacheDir:   *tlsCacheDir,
		BaseDomain: *baseDomain,
	}

	// Admin secret — default to webhook secret if not set separately
	adminSec := *adminSecret
	if adminSec == "" {
		adminSec = *webhookSecret
	}

	// Build server config
	cfg := api.Config{
		Host:        *host,
		Port:        *port,
		TLS:         tlsCfg,
		Auth:        authProvider,
		Registry:    registry,
		Store:       db,
		Events:      events,
		BaseDomain:  *baseDomain,
		AdminSecret: adminSec,
	}

	if *baseDomain != "" {
		log.Printf("subdomain routing: *.%s", *baseDomain)
	}

	// Dashboard
	if *dashPassword != "" {
		cfg.DashHandler = dash.EmbeddedHandler(dash.EmbeddedConfig{
			Password: *dashPassword,
			Store:    db,
			Events:   events,
		})
		log.Printf("dashboard: enabled at /dash")
	} else {
		log.Printf("dashboard: disabled (set --dash-password to enable)")
	}

	// Build and start server
	srv := api.NewServer(cfg)

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("received %s, shutting down gracefully...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	log.Printf("nullbore-server starting on %s:%s", *host, *port)
	if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
		log.Fatalf("server error: %v", err)
	}
	log.Printf("server stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
