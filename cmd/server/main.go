package main

import (
	"flag"
	"log"
	"os"

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
	apiKeys := flag.String("api-keys", envOr("NULLBORE_API_KEYS", ""), "Comma-separated API keys (dev mode)")
	dbPath := flag.String("db", envOr("NULLBORE_DB", "nullbore.db"), "SQLite database path")
	dashPassword := flag.String("dash-password", envOr("NULLBORE_DASH_PASSWORD", ""), "Dashboard password (empty = dashboard disabled)")
	flag.Parse()

	// Initialize store
	db, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer db.Close()
	log.Printf("database: %s", *dbPath)

	// Initialize auth provider
	authProvider := auth.NewStaticProvider(*apiKeys)

	// Initialize tunnel registry
	registry := tunnel.NewRegistry()

	// Start TTL reaper
	go registry.StartReaper()

	// Build server config
	cfg := api.Config{
		Host:     *host,
		Port:     *port,
		TLSCert:  *tlsCert,
		TLSKey:   *tlsKey,
		Auth:     authProvider,
		Registry: registry,
		Store:    db,
	}

	// Dashboard
	if *dashPassword != "" {
		cfg.DashHandler = dash.Handler(dash.Config{
			Password: *dashPassword,
			Store:    db,
		})
		log.Printf("dashboard: enabled at /dash")
	} else {
		log.Printf("dashboard: disabled (set --dash-password to enable)")
	}

	// Build and start server
	srv := api.NewServer(cfg)

	log.Printf("nullbore-server starting on %s:%s", *host, *port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
