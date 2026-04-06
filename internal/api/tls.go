package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// DomainChecker checks if a domain is a registered custom domain.
type DomainChecker interface {
	Resolve(domain string) (slug string, userID string, err error)
}

// TLSConfig holds TLS-related settings.
type TLSConfig struct {
	// Manual cert/key paths
	CertFile string
	KeyFile  string

	// Auto ACME (Let's Encrypt)
	Domains    []string // e.g. ["tunnel.nullbore.com"]
	CacheDir   string   // defaults to ~/.nullbore/certs
	Email      string   // optional, for Let's Encrypt notifications
	BaseDomain    string // if set, auto-cert {slug}.basedomain subdomains on demand
	AccountDomain string // if set, supports account routing hosts like {tunnel}.{account}.accountDomain

	// Custom domain support — check if a domain is registered before issuing certs
	DomainChecker DomainChecker
}

// IsEnabled returns true if any TLS mode is configured.
func (t *TLSConfig) IsEnabled() bool {
	return (t.CertFile != "" && t.KeyFile != "") || len(t.Domains) > 0
}

// IsACME returns true if automatic certificate management is configured.
func (t *TLSConfig) IsACME() bool {
	return len(t.Domains) > 0
}

// BuildTLSConfig returns a *tls.Config and optional ACME manager.
// For ACME mode, also starts an HTTP-01 challenge listener on :80.
func (t *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	if t.CertFile != "" && t.KeyFile != "" {
		// Manual mode — verify files exist
		if _, err := os.Stat(t.CertFile); err != nil {
			return nil, fmt.Errorf("TLS cert not found: %s", t.CertFile)
		}
		if _, err := os.Stat(t.KeyFile); err != nil {
			return nil, fmt.Errorf("TLS key not found: %s", t.KeyFile)
		}

		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert: %w", err)
		}

		// If custom domain support is enabled, set up autocert for those
		// while keeping the wildcard cert for NullBore subdomains
		if t.DomainChecker != nil {
			cacheDir := t.CacheDir
			if cacheDir == "" {
				home, _ := os.UserHomeDir()
				if home == "" {
					cacheDir = "/tmp/nullbore-certs"
				} else {
					cacheDir = filepath.Join(home, ".nullbore", "certs")
				}
			}
			os.MkdirAll(cacheDir, 0700)

			checker := t.DomainChecker
			accountSuffix := ""
			if t.AccountDomain != "" {
				accountSuffix = "." + t.AccountDomain
			}
			manager := &autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(cacheDir),
				HostPolicy: func(ctx context.Context, host string) error {
					// Allow account subdomain hosts (e.g. web.heroapp.nullbore.com)
					if accountSuffix != "" && strings.HasSuffix(host, accountSuffix) && host != t.AccountDomain {
						left := strings.TrimSuffix(host, accountSuffix)
						if left != "" && strings.Count(left, ".") <= 1 {
							return nil
						}
					}
					// Otherwise only allow registered custom domains
					_, _, err := checker.Resolve(host)
					if err != nil {
						return fmt.Errorf("host %q not a registered custom/account domain", host)
					}
					return nil
				},
			}
			if t.Email != "" {
				manager.Email = t.Email
			}

			log.Printf("tls: custom domain autocert enabled (cache: %s)", cacheDir)

			// Start HTTP-01 challenge handler on :80
			go func() {
				h := manager.HTTPHandler(httpRedirectHandler())
				log.Printf("tls: HTTP-01 challenge listener on :80")
				if err := http.ListenAndServe(":80", h); err != nil {
					log.Printf("tls: HTTP challenge listener error: %v", err)
				}
			}()

			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					name := hello.ServerName

					// Use wildcard cert for NullBore subdomains and the base domain
					if t.BaseDomain != "" {
						if name == t.BaseDomain || strings.HasSuffix(name, "."+t.BaseDomain) {
							return &cert, nil
						}
					}

					// Try autocert for custom domains
					return manager.GetCertificate(hello)
				},
			}, nil
		}

		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	if len(t.Domains) > 0 {
		return t.buildACMEConfig()
	}

	return nil, fmt.Errorf("no TLS configuration provided")
}

func (t *TLSConfig) buildACMEConfig() (*tls.Config, error) {
	cacheDir := t.CacheDir
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			cacheDir = "/tmp/nullbore-certs"
		} else {
			cacheDir = filepath.Join(home, ".nullbore", "certs")
		}
	}

	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("creating cert cache dir: %w", err)
	}

	manager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		HostPolicy: t.hostPolicy(),
	}

	if t.Email != "" {
		manager.Email = t.Email
	}

	log.Printf("tls: ACME enabled for domains %v (cache: %s)", t.Domains, cacheDir)

	// Start HTTP-01 challenge handler on :80
	go func() {
		h := manager.HTTPHandler(httpRedirectHandler())
		log.Printf("tls: HTTP-01 challenge listener on :80")
		if err := http.ListenAndServe(":80", h); err != nil {
			log.Printf("tls: HTTP challenge listener error: %v", err)
		}
	}()

	return manager.TLSConfig(), nil
}

// hostPolicy returns an autocert.HostPolicy that accepts:
// 1. Explicitly listed domains (from -tls-domain)
// 2. Any {slug}.baseDomain subdomain (if BaseDomain is set)
// 3. Account hosts like {account}.accountDomain and {tunnel}.{account}.accountDomain
func (t *TLSConfig) hostPolicy() autocert.HostPolicy {
	// Build whitelist set for fast lookup
	allowed := make(map[string]bool, len(t.Domains))
	for _, d := range t.Domains {
		allowed[d] = true
	}

	suffix := ""
	if t.BaseDomain != "" {
		suffix = "." + t.BaseDomain
	}
	accountSuffix := ""
	if t.AccountDomain != "" {
		accountSuffix = "." + t.AccountDomain
	}

	return func(ctx context.Context, host string) error {
		// Check explicit whitelist
		if allowed[host] {
			return nil
		}
		// Check {slug}.baseDomain pattern
		if suffix != "" && strings.HasSuffix(host, suffix) {
			slug := strings.TrimSuffix(host, suffix)
			if slug != "" && !strings.Contains(slug, ".") {
				return nil
			}
		}
		// Check account domain hosts: {account}.domain or {tunnel}.{account}.domain
		if accountSuffix != "" && strings.HasSuffix(host, accountSuffix) && host != t.AccountDomain {
			left := strings.TrimSuffix(host, accountSuffix)
			if left != "" && strings.Count(left, ".") <= 1 {
				return nil
			}
		}
		return fmt.Errorf("host %q not allowed", host)
	}
}

// httpRedirectHandler returns a handler that redirects HTTP to HTTPS.
func httpRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
