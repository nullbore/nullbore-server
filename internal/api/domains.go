package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DomainResolver resolves custom domains to tunnel slugs.
// Queries the dashboard API and caches results.
type DomainResolver struct {
	dashboardURL string
	secret       string
	client       *http.Client

	mu    sync.RWMutex
	cache map[string]*domainEntry
}

type domainEntry struct {
	slug      string
	userID    string
	fetchedAt time.Time
	err       error // nil if found
}

const domainCacheTTL = 2 * time.Minute

// NewDomainResolver creates a resolver that queries the dashboard for domain→slug mapping.
func NewDomainResolver(dashboardURL, secret string) *DomainResolver {
	return &DomainResolver{
		dashboardURL: dashboardURL,
		secret:       secret,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        make(map[string]*domainEntry),
	}
}

// Resolve returns the tunnel slug and user ID for a custom domain.
func (dr *DomainResolver) Resolve(domain string) (slug string, userID string, err error) {
	domain = strings.ToLower(domain)

	dr.mu.RLock()
	entry, ok := dr.cache[domain]
	dr.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < domainCacheTTL {
		if entry.err != nil {
			return "", "", entry.err
		}
		return entry.slug, entry.userID, nil
	}

	// Query dashboard
	slug, userID, err = dr.lookup(domain)

	// Cache result (even errors, to prevent hammering)
	dr.mu.Lock()
	dr.cache[domain] = &domainEntry{
		slug: slug, userID: userID,
		fetchedAt: time.Now(), err: err,
	}
	dr.mu.Unlock()

	return slug, userID, err
}

func (dr *DomainResolver) lookup(domain string) (string, string, error) {
	url := fmt.Sprintf("%s/internal/domain-lookup?domain=%s", dr.dashboardURL, domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Internal-Secret", dr.secret)

	resp, err := dr.client.Do(req)
	if err != nil {
		slog.Warn("domain lookup failed", "domain", domain, "error", err)
		return "", "", fmt.Errorf("domain lookup failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("domain %q not registered", domain)
	}

	var result struct {
		TunnelSlug string `json:"tunnel_slug"`
		UserID     string `json:"user_id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.TunnelSlug, result.UserID, nil
}

// IsCustomDomain checks if a hostname is a custom domain (not a NullBore subdomain).
func IsCustomDomain(host, baseDomain string) bool {
	if baseDomain == "" {
		return false
	}
	// Strip port
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	// It's a custom domain if it doesn't end with .baseDomain and isn't baseDomain itself
	return host != baseDomain && !strings.HasSuffix(host, "."+baseDomain)
}

// StartCacheReaper periodically cleans expired domain cache entries.
func (dr *DomainResolver) StartCacheReaper() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			dr.mu.Lock()
			for k, v := range dr.cache {
				if time.Since(v.fetchedAt) > domainCacheTTL*3 {
					delete(dr.cache, k)
				}
			}
			dr.mu.Unlock()
		}
	}()
}
