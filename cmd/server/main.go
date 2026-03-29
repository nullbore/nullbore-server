package main

import (
	"flag"
	"log"
	"os"

	"github.com/nullbore/nullbore-server/internal/api"
	"github.com/nullbore/nullbore-server/internal/auth"
	"github.com/nullbore/nullbore-server/internal/tunnel"
)

func main() {
	port := flag.String("port", envOr("NULLBORE_PORT", "8443"), "Server listen port")
	host := flag.String("host", envOr("NULLBORE_HOST", "0.0.0.0"), "Bind address")
	tlsCert := flag.String("tls-cert", envOr("NULLBORE_TLS_CERT", ""), "TLS certificate path")
	tlsKey := flag.String("tls-key", envOr("NULLBORE_TLS_KEY", ""), "TLS key path")
	apiKeys := flag.String("api-keys", envOr("NULLBORE_API_KEYS", ""), "Comma-separated API keys (dev mode)")
	flag.Parse()

	// Initialize auth provider
	authProvider := auth.NewStaticProvider(*apiKeys)

	// Initialize tunnel registry
	registry := tunnel.NewRegistry()

	// Start TTL reaper
	go registry.StartReaper()

	// Build and start server
	srv := api.NewServer(api.Config{
		Host:     *host,
		Port:     *port,
		TLSCert:  *tlsCert,
		TLSKey:   *tlsKey,
		Auth:     authProvider,
		Registry: registry,
	})

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
